package main

type ConfigData struct {
	Servers []Server `yaml:"Servers"`
}

type Server struct {
	Bindings       []string        `yaml:"Bindings"`
	Certificates   []Certificate   `yaml:"Certificates"`
	VirtualServers []VirtualServer `yaml:"VirtualServers"`
}

type Certificate struct {
	Fullchain string `yaml:"Fullchain"`
	Privkey   string `yaml:"Privkey"`
}

type VirtualServer struct {
	Hostname string `yaml:"Hostname"`
	Upstream string `yaml:"Upstream"`
}
