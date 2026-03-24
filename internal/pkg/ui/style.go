package ui

import "fmt"

const (
	Reset  = "\033[0m"
	Bold   = "\033[1m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Purple = "\033[35m"
	Cyan   = "\033[36m"
	White  = "\033[37m"
)

func DrawBox(title, content string, width int) string {
	top := "┌─" + title + " "
	for i := len(top); i < width; i++ {
		top += "─"
	}
	top += "┐"
	bottom := "└"
	for i := 0; i < width; i++ {
		bottom += "─"
	}
	bottom += "┘"

	return fmt.Sprintf("%s\n%s\n%s", top, content, bottom)

}
