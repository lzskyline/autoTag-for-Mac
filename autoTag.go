package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// 准备匹配、打标签的关键字列表
var keywords = []string{"零信任", "SDL", "等保", "字节跳动", "DDoS", "HIDS", "WAF", "物联网", "数据安全", "BAS", "58同城", "长亭", "NIDS", "Java安全", "应用安全", "安全规范"}

// 检查文件名是否包含关键字，并返回匹配到的关键字
func checkKeywords(path string, filename string) string {
	for _, keyword := range keywords {
		// 忽略大小写
		if strings.Contains(strings.ToLower(filename), strings.ToLower(keyword)) {
			addTag(path, keyword)
			fmt.Printf("文件 %s 增加了标签 %s\n", path, keyword)
		}
	}
	return ""
}

// 给文件增加一个Mac标签
func addTag(filename, tag string) error {
	// 使用xattr命令来设置文件的扩展属性，其中com.apple.metadata:_kMDItemUserTags是用于存储Mac标签的属性
	cmd := fmt.Sprintf("xattr -w com.apple.metadata:_kMDItemUserTags '(\"%s\")' \"%s\"", tag, filename)
	// 使用os/exec包来执行命令
	_, err := exec.Command("sh", "-c", cmd).Output()
	return err
}

// 遍历指定目录下的所有文件，并调用checkKeywords和addTag函数
func walkDir(dir string) error {
	// 使用filepath包来遍历目录
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// 如果不是目录
		if !info.IsDir() {
			// 取文件名
			filename := info.Name()
			// 检查文件名是否包含关键字
			checkKeywords(path, filename)
		}
		return nil
	})
}

func main() {
	// 定义一个目录变量，可以根据需要修改
	dir := "/Users/lzskyline/"
	// 遍历打标签
	err := walkDir(dir)
	if err != nil {
		fmt.Println(err)
	}
}
