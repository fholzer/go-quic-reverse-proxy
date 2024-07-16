package main

type ConfigData struct {
	Servers []Server `yaml:"Servers"`
}

type Server struct {
	Bindings       []Binding       `yaml:"Bindings"`
	Certificates   []Certificate   `yaml:"Certificates"`
	VirtualServers []VirtualServer `yaml:"VirtualServers"`
}

type Binding struct {
	Server       string `yaml:"Server"`
	Metrics      string `yaml:"Metrics"`
	VerifyClient bool   `yaml:"VerifyClient"`
	ClientCA     string `yaml:"ClientCA"`
}

type Certificate struct {
	Fullchain string `yaml:"Fullchain"`
	Privkey   string `yaml:"Privkey"`
}

type VirtualServer struct {
	Hostname   string `yaml:"Hostname"`
	Upstream   string `yaml:"Upstream"`
	ClientCert string `yaml:"ClientCert"`
	ClientKey  string `yaml:"ClientKey"`
}
