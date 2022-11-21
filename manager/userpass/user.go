package userpass

type User struct {
	ID       uint64
	UserName string
	CreateAt int64
	ExData   map[string]interface{}
}
