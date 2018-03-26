package main

type ConfigData struct {
	Servers []Server
}

type Server struct {
	Bindings       []string
	Certificates   []Certificate
	VirtualServers []VirtualServer
}

type Certificate struct {
	Fullchain string
	Privkey   string
}

type VirtualServer struct {
	Hostname string
	Upstream string
}
