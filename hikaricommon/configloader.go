package hikaricommon

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

func LoadConfig(filePath string, config interface{}) {
	log.Printf("loading config file '%v'\n", filePath)

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatalf("read config file '%v' err, %v\n", filePath, err)
	}

	json.Unmarshal(data, config)
	log.Printf("using config file '%v'\n", filePath)
	log.Println("config:\n", string(data))
}
