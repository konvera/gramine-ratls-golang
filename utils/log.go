package utils

import (
	"log"
	"os"
)

var Debug bool = os.Getenv("DEBUG") == "1"

func PrintDebug(args ...interface{}) {
	if Debug {
		log.Println(args...)
	}
}
