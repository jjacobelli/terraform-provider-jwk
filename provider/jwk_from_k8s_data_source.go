package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &JwkFromK8sDataSource{}

type JwkFromK8sDataSource struct{}

type JwkFromK8sDataSourceModel struct {
	ClientCertificate    types.String `tfsdk:"client_certificate"`
	ClientKey            types.String `tfsdk:"client_key"`
	ClusterCACertificate types.String `tfsdk:"cluster_ca_certificate"`
	Host                 types.String `tfsdk:"host"`
	Id                   types.String `tfsdk:"id"`
	Jwks                 types.List   `tfsdk:"jwks"`
	Token                types.String `tfsdk:"token"`
	Exec                 *ExecModel   `tfsdk:"exec"`
}

type ExecModel struct {
	APIVersion string            `tfsdk:"api_version"`
	Command    string            `tfsdk:"command"`
	Args       []string          `tfsdk:"args"`
	Env        map[string]string `tfsdk:"env"`
}

type JwksResp struct {
	Keys []json.RawMessage `json:"keys"`
}

func NewJwkFromK8sDataSource() datasource.DataSource {
	return &JwkFromK8sDataSource{}
}

func (d *JwkFromK8sDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_from_k8s"
}

func (d *JwkFromK8sDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "This data source can be used to fetcks JWKs from a K8S cluster",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "ID",
				Computed:            true,
			},
			"client_certificate": schema.StringAttribute{
				MarkdownDescription: "K8S Client Certificate. Required with `client_key` when neither `token` nor `exec` is set.",
				Optional:            true,
			},
			"client_key": schema.StringAttribute{
				MarkdownDescription: "K8S Client Key. Required with `client_certificate` when neither `token` nor `exec` is set.",
				Optional:            true,
				Sensitive:           true,
			},
			"cluster_ca_certificate": schema.StringAttribute{
				MarkdownDescription: "K8S Cluster Certificate",
				Required:            true,
			},
			"host": schema.StringAttribute{
				MarkdownDescription: "K8S Host",
				Required:            true,
			},
			"jwks": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of JWKs",
				Computed:            true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "K8S bearer token, used instead of `client_certificate` and `client_key`",
				Optional:            true,
				Sensitive:           true,
			},
			"exec": schema.SingleNestedAttribute{
				MarkdownDescription: "Credential plugin that returns a bearer token, like the `exec` block of the kubernetes provider",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"api_version": schema.StringAttribute{
						MarkdownDescription: "ExecCredential API version, e.g. `client.authentication.k8s.io/v1`",
						Required:            true,
					},
					"command": schema.StringAttribute{
						MarkdownDescription: "Command to run",
						Required:            true,
					},
					"args": schema.ListAttribute{
						ElementType:         types.StringType,
						MarkdownDescription: "Command arguments",
						Optional:            true,
					},
					"env": schema.MapAttribute{
						ElementType:         types.StringType,
						MarkdownDescription: "Extra environment variables for the command",
						Optional:            true,
					},
				},
			},
		},
	}
}

func (d *JwkFromK8sDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
}

func (d *JwkFromK8sDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data JwkFromK8sDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	token := data.Token.ValueString()
	certStr := data.ClientCertificate.ValueString()
	keyStr := data.ClientKey.ValueString()
	if token != "" && data.Exec != nil {
		resp.Diagnostics.AddError("Auth", "Set only one of token or exec")
		return
	}
	if token == "" && data.Exec == nil && (certStr == "" || keyStr == "") {
		resp.Diagnostics.AddError("Auth", "Set token, exec, or both client_certificate and client_key")
		return
	}
	if data.Exec != nil {
		var err error
		token, err = execToken(ctx, data.Exec)
		if err != nil {
			resp.Diagnostics.AddError("Exec", err.Error())
			return
		}
	}

	var certs []tls.Certificate
	if token == "" {
		cert, err := tls.X509KeyPair([]byte(certStr), []byte(keyStr))
		if err != nil {
			resp.Diagnostics.AddError("X509KeyPair", fmt.Sprintf("Can't create X509: %s", err))
			return
		}
		certs = append(certs, cert)
	}

	host := strings.TrimRight(data.Host.ValueString(), "/")
	keys, err := fetchJwks(ctx, host, data.ClusterCACertificate.ValueString(), certs, token)
	if err != nil {
		resp.Diagnostics.AddError("Fetch JWKS", err.Error())
		return
	}

	var jwksAttr []attr.Value
	for _, jwkRaw := range keys {
		jwk, err := json.Marshal(&jwkRaw)
		if err != nil {
			resp.Diagnostics.AddError("Marshal", fmt.Sprintf("Can't marshal jwkRaw : %s", err))
			return
		}
		jwksAttr = append(jwksAttr, types.StringValue(string(jwk)))
	}

	data.Id = types.StringValue(host)
	data.Jwks, _ = types.ListValue(types.StringType, jwksAttr)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func fetchJwks(ctx context.Context, host, caPEM string, certs []tls.Certificate, token string) ([]json.RawMessage, error) {
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM([]byte(caPEM)); !ok {
		return nil, fmt.Errorf("can't load cluster CA")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: certs,
		RootCAs:      caCertPool,
	}}}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, host+"/openid/v1/jwks", nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	k8sResp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fail to query K8S cluster: %w", err)
	}
	defer k8sResp.Body.Close()

	jwksData, err := io.ReadAll(k8sResp.Body)
	if err != nil {
		return nil, fmt.Errorf("fail to read resp: %w", err)
	}
	if k8sResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("K8S cluster returned HTTP %d: %s", k8sResp.StatusCode, jwksData)
	}

	var jwksResp JwksResp
	if err := json.Unmarshal(jwksData, &jwksResp); err != nil {
		return nil, fmt.Errorf("can't unmarshal JwksResp: %w", err)
	}
	return jwksResp.Keys, nil
}

func execToken(ctx context.Context, e *ExecModel) (string, error) {
	info, err := json.Marshal(map[string]any{
		"apiVersion": e.APIVersion,
		"kind":       "ExecCredential",
		"spec":       map[string]any{"interactive": false},
	})
	if err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, e.Command, e.Args...)
	cmd.Env = append(os.Environ(), "KUBERNETES_EXEC_INFO="+string(info))
	for k, v := range e.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("credential command %q failed: %w: %s", e.Command, err, stderr.String())
	}

	var cred struct {
		Status struct {
			Token string `json:"token"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &cred); err != nil {
		return "", fmt.Errorf("can't parse ExecCredential from %q: %w", e.Command, err)
	}
	if cred.Status.Token == "" {
		return "", fmt.Errorf("ExecCredential from %q has no status.token", e.Command)
	}
	return cred.Status.Token, nil
}
