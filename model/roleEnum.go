package model

type Role int

func (r Role) String() string {
	return roles[r]
}

const (
	Admin Role = iota
	Dean
	Student
)

var roles = []string{
	Admin:   "Admin",
	Dean:    "Dean",
	Student: "Student",
}
