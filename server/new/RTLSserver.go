package new

import (
	"log"
	"net/http"
	"github.com/gin-gonic/gin"
	"fmt"
	"flag"
	"strings"
	"strconv"
	"sync"
	"io/ioutil"
	"encoding/json"
)

// server status file structure, useful for restoring status after restart server
var switches = struct {
	sync.RWMutex
	m map[string]groupStatus
}{m: make(map[string]groupStatus)}

type groupStatus struct {
	Track          bool   `json:"track"`
	Users          string `json:"users"`
	Location       string `json:"location"`
	RemainingCount int    `json:"remaining_count"`
	UseBulk        bool   `json:"use_bulk"`
}

// Commandline Arguments variable
var ServerAddress, Group, Port string
var MinimumNumberOfRouters, MinRSSI, CollectionTime int

var usageGuide = `RTLS Server

Routes available:

GET /api/switch - for switch between learning and tracking

	- if you want to track, use GET /api/switch?group=GROUPNAME
	- if you want to learn, use GET /api/switch?group=group&user=mac1,mac2,mac3&location=location
	  where group is the group name;
	  and mac1,mac2,... are the macs of the devices you are using for learning;
	  and location is name of location you are trying to learn;

GET|POST /api/status - for getting status of a group
	
	- use GET /api/status?group=GROUPNAME
`

func main() {
	// command line arguments
	flag.StringVar(&Port, "port", "8072", "port to run this server on it - local (default: 8072)")
	flag.StringVar(&ServerAddress, "server", "http://104.237.255.199:18003", "address & port of main IPS server, in format of 'http://ADDRESS:PORT' should include http or https")
	flag.IntVar(&MinimumNumberOfRouters, "min", 1, "minimum number of routers before sending fingerprint (default: 1)")
	flag.IntVar(&MinRSSI, "rssi", -110, "minimum RSSI that must exist to send on (default: -110)")
	flag.IntVar(&CollectionTime, "time", 3, "collection time to average fingerprints (in seconds - default: 3")

	// pars arguments
	flag.Parse()

	// web server configurations
	gin.SetMode(gin.ReleaseMode)

	router := gin.Default()
	log.Println("Starting...")

	// set templates and static files of gin
	router.Static("/static", "./static")
	router.LoadHTMLGlob("templates/*")

	// main page route
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", gin.H{})
	})

	// bulk learn page

	router.GET("/auto", func(c *gin.Context) {
		c.HTML(http.StatusOK, "auto_learn.tmpl", gin.H{})
	})

	api := router.Group("/api")

	api.GET("/status", getRtlsStatus)
	api.POST("/status", getRtlsStatus)
	api.GET("/switch", switchMode)

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

func setGroupStatus(group string, data groupStatus) {
	switches.Lock()
	switches.m[group] = data
	bJson, _ := json.MarshalIndent(switches.m, "", "\t")
	ioutil.WriteFile("switches.json", bJson, 0644)
	switches.Unlock()
}
