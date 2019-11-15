package database

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/Shopify/yaml"
	"github.com/jaeles-project/jaeles/database/models"
	"github.com/jaeles-project/jaeles/libs"
)

// CleanSigns clean all signature
func CleanSigns() {
	var signs []models.Signature
	DB.Find(&signs)
	DB.Unscoped().Delete(&signs)
}

// SelectSign select signature to gen request
func SelectSign(signName string) []string {
	var signs []models.Signature
	if signName == "*" || signName == "" {
		DB.Find(&signs)
	} else {
		DB.Where("sign_id LIKE ? OR name LIKE ?", fmt.Sprintf("%%%v%%", signName), fmt.Sprintf("%%%v%%", signName)).Find(&signs)
	}

	var selectedSigns []string
	for _, sign := range signs {
		selectedSigns = append(selectedSigns, sign.AsbPath)
	}
	return selectedSigns
}

// ImportSign import signature to DB
func ImportSign(signPath string) {
	sign, err := ParseSignature(signPath)
	if err != nil {
		log.Printf("Error parsing YAML sign %v \n", signPath)
	}

	if sign.Info.Category == "" {
		if strings.Contains(sign.ID, "-") {
			sign.Info.Category = strings.Split(sign.ID, "-")[0]
		} else {
			sign.Info.Category = sign.ID
		}
	}
	if sign.Info.Name == "" {
		sign.Info.Name = sign.ID
	}

	signObj := models.Signature{
		Name:     sign.Info.Name,
		Category: sign.Info.Category,
		Risk:     sign.Info.Risk,
		Tech:     sign.Info.Tech,
		OS:       sign.Info.OS,
		SignID:   sign.ID,
		AsbPath:  signPath,
		Type:     sign.Type,
	}
	DB.Create(&signObj)
}

// ParseSignature Parsing signature
func ParseSignature(signFile string) (sign libs.Signature, err error) {
	yamlFile, err := ioutil.ReadFile(signFile)
	if err != nil {
		log.Printf("Error parsing %v", signFile)
	}
	err = yaml.Unmarshal(yamlFile, &sign)
	if err != nil {
		log.Printf("Error parsing %v", signFile)
	}
	return sign, err
}
