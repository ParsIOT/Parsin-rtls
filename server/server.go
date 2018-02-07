// Copyright 2015-2017 Zack Scholl. All rights reserved.
// Use of this source code is governed by a AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"strconv"

	"github.com/gin-gonic/gin"
)

// TESTING
// curl -H "Content-Type: application/json" -X POST -d '{"node": "node1", "group": "r", "signals": [{"rssi": -45, "mac": "80:37"},{"rssi": -80, "mac": "99:99"},{"rssi": -60, "mac": "11:11"}], "timestamp": 1439596562110}' http://127.0.0.1:8072/post
// curl -H "Content-Type: application/json" -X POST -d '{"node": "node2", "group": "r", "signals": [{"rssi": -32, "mac": "80:37"},{"rssi": -89, "mac": "11:11"}], "timestamp": 1439596562110}' http://127.0.0.1:8072/post
// curl -H "Content-Type: application/json" -X POST -d '{"node": "node3", "group": "r", "signals": [{"rssi": -55, "mac": "99:99"},{"rssi": -78, "mac": "11:11"}], "timestamp": 1439596562110}' http://127.0.0.1:8072/post

// Fingerprint to send to FIND
type Fingerprint struct {
	Group           string   `json:"group"`
	Username        string   `json:"username"`
	Location        string   `json:"location"`
	Timestamp       int64    `json:"timestamp"`
	WifiFingerprint []Router `json:"wifi-fingerprint"`
}

// Router is the router information for each invdividual mac address
// needed for Fingerprint
type Router struct {
	Mac  string `json:"mac"`
	Rssi int    `json:"rssi"`
}

type groupStatus struct {
	Track          bool   `json:"track"`
	Users          string `json:"users"`
	Location       string `json:"location"`
	RemainingCount int    `json:"remaining_count"`
	UseBulk        bool   `json:"use_bulk"`
}

var count = 10

// ReverseFingerprint is sent from each node
type ReverseFingerprint struct {
	Node  string `json:"node"`
	Group string `json:"group"`
	Signals []struct {
		Mac  string `json:"mac"`
		Rssi int    `json:"rssi"`
	} `json:"signals"`
	Timestamp int `json:"timestamp"`
}

var fingerprints = struct {
	sync.RWMutex
	m map[string]map[string]map[string]int
}{m: make(map[string]map[string]map[string]int)}

type bulkWrapper struct {
	Data []Fingerprint `json:"fingerprints"`
}

type BulkLearnData struct {
	sync.RWMutex
	m map[string]map[string][]Fingerprint
}

var bulkData = BulkLearnData{m: make(map[string]map[string][]Fingerprint)}

var switches = struct {
	sync.RWMutex
	m map[string]groupStatus
}{m: make(map[string]groupStatus)}

var ServerAddress, Group, Port string
var MinimumNumberOfRouters, MinRSSI, CollectionTime int

var usageGuide = `RTLS Server

Routes available:

GET /switch - for learning and tracking

- if you want to track, use GET /switch?group=GROUPNAME
- if you want to learn, use GET /switch?group=group&user=mac1,mac2,mac3&location=location
  where group is the group name
  where mac1,mac2,... are the macs of the devices you are using for learning
  where location is the location you are trying to learn
`

func main() {
	gin.SetMode(gin.ReleaseMode)

	flag.StringVar(&Port, "port", "8072", "port to run this server on (default: 8072)")
	//flag.StringVar(&ServerAddress, "server", "https://ml.internalpositioning.com", "address to FIND server")
	flag.StringVar(&ServerAddress, "server", "http://104.237.255.199:18003", "address to FIND server")
	flag.IntVar(&MinimumNumberOfRouters, "min", 0, "minimum number of routers before sending fingerprint")
	flag.IntVar(&MinRSSI, "rssi", -110, "minimum RSSI that must exist to send on")
	flag.IntVar(&CollectionTime, "time", 3, "collection time to average fingerprints (in seconds)")
	flag.Parse()

	router := gin.Default()
	log.Println("Starting...")

	// Start parsing fingerprints
	go parseFingerprints()

	// Setup switches
	switches.Lock()
	switches.m = make(map[string]groupStatus)
	if _, err := os.Stat("switches.json"); err == nil {
		bJson, _ := ioutil.ReadFile("switches.json")
		json.Unmarshal(bJson, &switches.m)
	}
	switches.Unlock()

	// Route handling

	router.Static("/static", "./static")
	router.LoadHTMLGlob("templates/*")
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", gin.H{})
	})
	router.GET("/auto", func(c *gin.Context) {
		c.HTML(http.StatusOK, "auto_learn.tmpl", gin.H{})
	})
	router.POST("/reversefingerprint", func(c *gin.Context) {
		var json ReverseFingerprint
		err := c.BindJSON(&json)
		if err == nil {
			process(json)
		} else {
			log.Println(err)
		}
		c.String(http.StatusOK, "recieved")
	})
	router.GET("/status", getRtlsStatus)
	router.POST("/status", getRtlsStatus)
	router.GET("/switch", switchMode)

	fmt.Println("Running on 127.0.0.1:" + Port)
	router.Run(":" + Port)
}

func getRtlsStatus(c *gin.Context) {
	group := c.DefaultQuery("group", "")
	if len(group) == 0 {
		c.String(http.StatusBadRequest, "must include group name!\n\n"+usageGuide)
		return
	}

	switches.Lock()
	dat, ok := switches.m[group]
	switches.Unlock()
	if ok {
		if !dat.Track {
			c.String(http.StatusOK, group + " set to learning at '" + strings.TrimSpace(dat.Location) + "' for user(s) '" + strings.TrimSpace(dat.Users) + "', '"+
				strings.TrimSpace(strconv.Itoa(dat.RemainingCount))+ "' Sample(s) remaining. Using Bulk mode is set to '"+ strings.TrimSpace(strconv.FormatBool(dat.UseBulk))+ "'")
		} else {
			c.String(http.StatusOK, group+" set to tracking")
		}
	} else {
		c.String(401, "group not found")
	}
}

func switchMode(c *gin.Context) {
	group := c.DefaultQuery("group", "")
	if len(group) == 0 {
		c.String(http.StatusBadRequest, "must include group name!\n\n"+usageGuide)
		return
	}

	user := strings.ToLower(strings.Replace(c.DefaultQuery("user", ""), ":", "", -1))
	if len(user) == 0 {
		//c.String(http.StatusBadRequest, "must include user!\n\n"+usageGuide)
		setGroupStatus(group, groupStatus{Track: true})
		c.String(http.StatusOK, group+" set to tracking")
		return
	}

	location := c.DefaultQuery("loc", "")
	if len(location) == 0 {
		c.String(http.StatusBadRequest, "must include location!\n\n"+usageGuide)
		return
	}

	count := 500
	if i, err := strconv.Atoi(c.DefaultQuery("count", "500")); err == nil {
		count = i
	}

	useBulk := true
	if i, err := strconv.ParseBool(c.DefaultQuery("bulk", "true")); err == nil {
		useBulk = i
	}

	setGroupStatus(group, groupStatus{false, user, location, count, useBulk})

	var message string
	if len(location) == 0 && len(user) == 0 {
		message = group + " set to tracking"
	} else {
		message = group + " set to learning at '" + location + "' for user '" + user + "' and '" + strconv.Itoa(count) + "' Samples. Using Bulk mode is set to '" + strconv.FormatBool(useBulk) + "'"
	}
	log.Println(message)
	c.String(http.StatusOK, message)
}

func process(json ReverseFingerprint) {
	json.Group = strings.ToLower(json.Group)
	fingerprints.Lock()
	if _, ok := fingerprints.m[json.Group]; !ok {
		fingerprints.m[json.Group] = make(map[string]map[string]int)
	}
	for _, signal := range json.Signals {
		fmt.Println(json.Node, signal.Mac, signal.Rssi)
		mac := strings.ToLower(json.Node)
		user := strings.Replace(strings.ToLower(signal.Mac), ":", "", -1)
		if _, ok := fingerprints.m[json.Group][user]; !ok {
			fingerprints.m[json.Group][user] = make(map[string]int)
		}
		if signal.Rssi > 0 {
			signal.Rssi = signal.Rssi * -1
		}
		fingerprints.m[json.Group][user][mac] = signal.Rssi
	}
	fingerprints.Unlock()
}

func parseFingerprints() {
	ticker := time.NewTicker(time.Duration(CollectionTime) * time.Second)
	for range ticker.C {

		fingerprints.Lock()
		go sendFingerprints(fingerprints.m)
		// clear fingerprints
		fingerprints.m = make(map[string]map[string]map[string]int)
		fingerprints.Unlock()
	}
}

func sendFingerprints(m map[string]map[string]map[string]int) {
	for group := range m {
		for user := range m[group] {
			// Define route and whether learning / tracking
			route := "/track"
			gs := getGroupStatus(group)
			if !gs.Track {
				if !strings.Contains(gs.Users, user) {
					continue // only insert if user is one of the users to use for learning (specified in route)
				}
				route = "/learn"
				if gs.RemainingCount < 1 {

					if gs.UseBulk {
						route = "/bulklearn"

						bulkData.Lock()
						data := bulkData.m[group][user]
						bulkData.m[group] = make(map[string][]Fingerprint)
						bulkData.Unlock()

						payloadBytes, err := json.Marshal(bulkWrapper{data})
						if err != nil {
							// handle err
						}

						log.Println("Sending to " + ServerAddress + route + ": " + string(payloadBytes))

						body := bytes.NewReader(payloadBytes)

						req, err := http.NewRequest("POST", ServerAddress+route, body)
						if err != nil {
							// handle err
						}
						req.Header.Set("Content-Type", "application/json")

						resp, err := http.DefaultClient.Do(req)
						if err != nil {
							// handle err
						} else {
							defer resp.Body.Close()
						}
					}

					log.Printf("learning user %s at %s done!", user, gs.Location)
					setGroupStatus(group, groupStatus{Track: true})
					log.Println(group + " set to tracking")
					return

				}
				log.Printf("sending data to learning user %s at %s\t-\t%d remaining", user, gs.Location, gs.RemainingCount)
				gs.RemainingCount--
				gs.Save(group)
			} else {
				gs.Location = "unknown"
			}

			// Require a minimum of routers to track
			if MinimumNumberOfRouters > len(m[group][user]) && route == "/track" {
				log.Printf("Not tracking %s in group %s because MinimumNumberOfRouters (%d) > num of routers in fingerprint (%d)", user, group, MinimumNumberOfRouters, len(m[group][user]))
				continue
			}

			data := Fingerprint{
				Username: strings.Replace(user, ":", "", -1),
				Group:    group,
				Location: gs.Location,
			}

			fingerprint := make([]Router, len(m[group][user]))
			num := 0
			maxRSSI := 0
			for mac := range m[group][user] {
				fingerprint[num].Mac = mac
				fingerprint[num].Rssi = m[group][user][mac]
				if fingerprint[num].Rssi > maxRSSI {
					maxRSSI = fingerprint[num].Rssi
				}
				num++
			}
			// Require a maximum RSSI of fingerprint to above minimum RSSI threshold to track
			if MinRSSI > maxRSSI && route == "/track" {
				log.Printf("Not tracking %s in group %s because MinRSSI (%d) > max RSSI of fingerprint (%d)", user, group, MinRSSI, maxRSSI)
				continue
			}
			data.WifiFingerprint = fingerprint

			if gs.UseBulk {
				log.Printf("Bulk Learn Mod!sending data to aborted -\t%d remaining", gs.RemainingCount)

				bulkData.Lock()
				if val, ok := bulkData.m[group]; ok {
					if v, ok := val[user]; ok {
						v = append(v, data)
						bulkData.m[group][user] = v
					} else {
						bulkData.m[group][user] = []Fingerprint{data}
					}
				} else {
					bulkData.m[group] = make(map[string][]Fingerprint)
					bulkData.m[group][user] = []Fingerprint{data}
				}
				bulkData.Unlock()
				continue
			}

			payloadBytes, err := json.Marshal(data)
			if err != nil {
				// handle err
			}

			log.Println("Sending to " + ServerAddress + route + ": " + string(payloadBytes))

			body := bytes.NewReader(payloadBytes)

			req, err := http.NewRequest("POST", ServerAddress+route, body)
			if err != nil {
				// handle err
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				// handle err
			} else {
				defer resp.Body.Close()
			}

			if gs.UseBulk {
				bulkData.Lock()
				bulkData.m = make(map[string]map[string][]Fingerprint)
				bulkData.Unlock()
			}
		}
	}
}

func setGroupStatus(group string, data groupStatus) {
	switches.Lock()
	switches.m[group] = data
	bJson, _ := json.MarshalIndent(switches.m, "", "\t")
	ioutil.WriteFile("switches.json", bJson, 0644)
	switches.Unlock()
}

func (gs *groupStatus) Save(group string) {
	setGroupStatus(group, *gs)
}

func getGroupStatus(name string) groupStatus {
	switches.Lock()
	data, ok := switches.m[name]
	switches.Unlock()
	if ok {
		return data
	}
	return groupStatus{Track: true}
}

func StrExtract(sExper, sAdelim, sCdelim string, nOccur int) string {

	aExper := strings.Split(sExper, sAdelim)

	if len(aExper) <= nOccur {
		return ""
	}

	sMember := aExper[nOccur]
	aExper = strings.Split(sMember, sCdelim)

	if len(aExper) == 1 {
		return ""
	}

	return aExper[0]
}
