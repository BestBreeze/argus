// preprocessor/preprocessor.go
package preprocessor

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ProcessInput 接收一个路径 (文件或目录), 返回一个可供扫描的目录路径。
// 如果输入是压缩包, 它会解压到临时目录并返回该目录路径。
// 返回的第二个值是一个清理函数，调用者必须在扫描结束后执行它。
func ProcessInput(path string) (scanPath string, cleanup func(), err error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", nil, fmt.Errorf("无法访问路径: %w", err)
	}

	// 默认的清理函数是空操作
	cleanup = func() {}

	// 如果输入是目录, 直接返回
	if info.IsDir() {
		return path, cleanup, nil
	}

	// 如果输入是文件, 检查是否为zip文件 (未来可扩展支持 .tar.gz, .jar)
	if filepath.Ext(path) == ".zip" {
		tempDir, err := os.MkdirTemp("", "argus-unzip-")
		if err != nil {
			return "", nil, fmt.Errorf("创建临时目录失败: %w", err)
		}

		// 设置清理函数，以便之后删除临时目录
		cleanup = func() {
			fmt.Printf("清理临时目录: %s\n", tempDir)
			os.RemoveAll(tempDir)
		}

		fmt.Printf("检测到ZIP压缩包, 正在解压到: %s\n", tempDir)
		if err := unzip(path, tempDir); err != nil {
			cleanup() // 如果解压失败，也要执行清理
			return "", nil, fmt.Errorf("解压失败: %w", err)
		}
		return tempDir, cleanup, nil
	}

	return "", nil, fmt.Errorf("不支持的输入文件类型: %s", path)
}

// unzip 是一个辅助函数，用于解压zip文件
func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)

		// 修复潜在的 Zip Slip 漏洞
		if !filepath.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("非法的文件路径: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		_, err = io.Copy(outFile, rc)

		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
}
