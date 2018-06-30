/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package scp

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gravitational/teleport/lib/httplib"

	"github.com/gravitational/trace"
)

const (
	// 644 means that files are readable and writeable by the owner of
	// the file and readable by users in the group owner of that file
	// and readable by everyone else.
	httpUploadFileMode = 0644
)

func CreateHTTPUploadCommand(newFilePath string, request *http.Request, progress io.Writer) (Command, error) {
	if request == nil {
		return nil, trace.BadParameter("request cannot be nil")
	}

	dir, filename := filepath.Split(newFilePath)
	if filename == "" {
		return nil, trace.BadParameter("invalid file path: %v", filename)
	}

	contentLength := request.Header.Get("Content-Length")
	fileSize, err := strconv.ParseInt(contentLength, 10, 0)
	if err != nil {
		return nil, trace.BadParameter("invalid Content-Length header")
	}

	fs := &httpFileSystem{
		reader:   request.Body,
		fileName: filename,
		fileSize: fileSize,
	}

	flags := Flags{
		Target: []string{dir},
	}

	cfg := Config{
		Flags:          flags,
		FileSystem:     fs,
		ProgressWriter: progress,
		RemoteLocation: dir,
	}

	cmd, err := CreateUploadCommand(cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return cmd, nil
}

func CreateHTTPDownloadCommand(remoteLocation string, w http.ResponseWriter, progress io.Writer) (Command, error) {
	_, filename := filepath.Split(remoteLocation)
	if filename == "" {
		return nil, trace.BadParameter("invalid file path: %v", filename)
	}

	flags := Flags{
		Target: []string{filename},
	}

	cfg := Config{
		Flags:          flags,
		ProgressWriter: progress,
		RemoteLocation: remoteLocation,
		FileSystem: &httpFileSystem{
			writer: w,
		},
	}

	cmd, err := CreateDownloadCommand(cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return cmd, nil
}

type httpFileSystem struct {
	writer   http.ResponseWriter
	reader   io.ReadCloser
	fileName string
	fileSize int64
}

func (l *httpFileSystem) SetChmod(path string, mode int) error {
	return nil
}

func (l *httpFileSystem) MkDir(path string, mode int) error {
	return trace.BadParameter("directories are not supported in http file transfer")
}

func (l *httpFileSystem) IsDir(path string) bool {
	return false
}

func (l *httpFileSystem) OpenFile(filePath string) (io.ReadCloser, error) {
	return l.reader, nil
}

func (l *httpFileSystem) CreateFile(filePath string, length uint64) (io.WriteCloser, error) {
	_, filename := filepath.Split(filePath)
	contentLength := strconv.FormatUint(length, 10)
	header := l.writer.Header()

	httplib.SetNoCacheHeaders(header)
	httplib.SetNoSniff(header)
	header.Set("Content-Length", contentLength)
	header.Set("Content-Type", "application/octet-stream")
	header.Set("Content-Disposition", fmt.Sprintf(`attachment;filename="%v"`, filename))
	return &nopWriteCloser{Writer: l.writer}, nil
}

func (l *httpFileSystem) GetFileInfo(filePath string) (FileInfo, error) {
	return &httpFileInfo{
		name: l.fileName,
		path: l.fileName,
		size: l.fileSize,
	}, nil
}

type httpFileInfo struct {
	path string
	name string
	size int64
}

func (l *httpFileInfo) IsDir() bool {
	return false
}

func (l *httpFileInfo) GetName() string {
	return l.name
}

func (l *httpFileInfo) GetPath() string {
	return l.path
}

func (l *httpFileInfo) GetSize() int64 {
	return l.size
}

func (l *httpFileInfo) ReadDir() ([]FileInfo, error) {
	return nil, trace.BadParameter("directories are not supported in http file transfer")
}

func (l *httpFileInfo) GetModePerm() os.FileMode {
	return httpUploadFileMode
}

type nopWriteCloser struct {
	io.Writer
}

func (wr *nopWriteCloser) Close() error {
	return nil
}
