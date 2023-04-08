// Package utils provide utility methods for other packages in the project.
package utils

import (
	"log"
	"os"
)

var Debug bool = os.Getenv("DEBUG") == "1"

// PrintDebug logs based on Debug flag.
func PrintDebug(args ...interface{}) {
	if Debug {
		log.Println(args...)
	}
}
