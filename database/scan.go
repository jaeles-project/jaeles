package database

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/jaeles-project/jaeles/database/models"
	"github.com/jaeles-project/jaeles/libs"
)

// CleanScans clean all scan
func CleanScans() {
	var scans []models.Scans
	DB.Find(&scans)
	DB.Unscoped().Delete(&scans)
}

// NewScan select signature to gen request
func NewScan(options libs.Options, mode string, signs []string) string {
	id, _ := uuid.NewUUID()
	rawScanID, _ := id.MarshalText()

	var shortSigns []string
	for _, signName := range signs {
		shortSigns = append(shortSigns, filepath.Base(signName))
	}
	signatures := strings.Join(shortSigns[:], ",")

	signObj := models.Scans{
		ScanID:      fmt.Sprintf("%x", rawScanID),
		SignatureID: signatures,
		OutputDir:   options.Output,
		Mode:        mode,
	}
	DB.Create(&signObj)
	return fmt.Sprintf("%v", signObj.ScanID)
}
