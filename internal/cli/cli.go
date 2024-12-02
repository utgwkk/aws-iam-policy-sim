package cli

type CLI struct {
	RoleName string `required:"" help:"IAM role name to simulate" long:"role-name"`

	Debug bool `help:"Enable debug output" long:"debug"`
}
