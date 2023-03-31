package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Rule struct {
	Keyword string
	Tags    []string
}

// 准备匹配、打标签的关键字列表
var rules = []Rule{
	{"反入侵", []string{"IDS", "WAF", "HIDS", "反入侵"}},
	{"等保", []string{"等级保护", "等保"}},
}

func checkKeywords(path string, contentSearch bool) ([]string, error) {
	filename := filepath.Base(path)
	matchedTags := make([]string, 0)
	for _, rule := range rules {
		// 忽略大小写
		if strings.Contains(strings.ToLower(filename), strings.ToLower(rule.Keyword)) {
			matchedTags = append(matchedTags, rule.Tags...)
		}
	}
	// 如果需要基于文件内容检索
	if contentSearch {
		content, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for _, rule := range rules {
			if strings.Contains(strings.ToLower(string(content)), strings.ToLower(rule.Keyword)) {
				matchedTags = append(matchedTags, rule.Tags...)
			}
		}
	}
	return matchedTags, nil
}

func addTag(filename string, tags []string) error {
	if len(tags) > 0 {
		for _, tag := range tags {
			cmd := fmt.Sprintf("xattr -w com.apple.metadata:_kMDItemUserTags '(\"%s\")' \"%s\"", tag, filename)
			_, err := exec.Command("sh", "-c", cmd).Output()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func walkDir(dir string, contentSearch bool) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			tags, err := checkKeywords(path, contentSearch)
			if err != nil {
				return err
			}
			err = addTag(path, tags)
			if err != nil {
				return err
			}
			if len(tags) > 0 {
				fmt.Printf("文件 %s 增加了标签 %v\n", path, tags)
			}
		}
		return nil
	})
}

func main() {
	dir := "/path/to/your/directory" // 修改为你需要处理的目录
	contentSearch := true            // 根据需要设置为true或false，决定是否需要基于文件内容检索

	err := walkDir(dir, contentSearch)
	if err != nil {
		fmt.Println(err)
	}
}
