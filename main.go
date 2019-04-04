package main

import (
  "bytes"
  "strconv"
  "strings"
  "time"
  "fmt"
  "os"
  "os/user"
  "io/ioutil"
  "log"
  "net/http"
  "net/url"
  "math/rand"
  "encoding/json"
  "encoding/base64"
  "gopkg.in/jcmturner/gokrb5.v7/spnego"
  "gopkg.in/jcmturner/gokrb5.v7/credentials"
  "gopkg.in/jcmturner/gokrb5.v7/client"
  "gopkg.in/jcmturner/gokrb5.v7/config"
)

const (
  EnvKrbCache = "KRB5CCNAME"
  EnvKrbConfig = "KRB5_CONFIG"
  EnvOidcAuthUrl = "OIDC_AUTH_URL"
  EnvOidcClientId = "OIDC_CLIENT_ID"
  EnvOidcRedirectUri = "OIDC_REDIRECT_URI"
  EnvOidcResponseType = "OIDC_RESPONSE_TYPE"
  EnvOidcScope = "OIDC_SCOPE"
  EnvDebugEnabled = "DEBUG"
)

var logger *log.Logger

type ExecCredential struct {
  ApiVersion string `json:"apiVersion"`
  Kind string `json:"kind"`
  Status ExecCredentialStatus `json:"status"`
}

type ExecCredentialStatus struct {
  Error string `json:"error,omitempty"` // Is this even valid?
  Token string `json:"token,omitempty"`
  Expiration string `json:"expirationTimestamp,omitempty"`
}

func init() {
  v, err := strconv.ParseBool(os.Getenv(EnvDebugEnabled))
  if v == false || err != nil {
    logger = log.New(ioutil.Discard, "debug: ", log.LstdFlags)
  } else {
    logger = log.New(os.Stderr, "debug: ", log.LstdFlags)
  }
}

func getEnvRequired(key string) (string, error) {
  if v, exists := os.LookupEnv(key); exists != true {
    return "", fmt.Errorf("missing environment variable %s", key)
  } else {
    logger.Printf("looking for %s, found %s", key, v)
    return v, nil
  }
}

func getEnvDefault(key, defaultValue string) (string) {
  if v, exists := os.LookupEnv(key); exists != true {
    logger.Printf("looking for %s, defaulting to %s", key, defaultValue)
    return defaultValue
  } else {
    logger.Printf("looking for %s, found %s", key, v)
    return v
  }
}

func getKrbCache(uid string) (string) {
  cache := getEnvDefault(EnvKrbCache, "/tmp/krb5cc_%s")
  n := strings.Count(cache, "%s")
  if n > 0 {
    cache = fmt.Sprintf(cache, uid)
  }

  result := strings.TrimPrefix(cache, "FILE:")
  logger.Printf("for %s had %s parsed to %s", EnvKrbCache, cache, result)

  return result
}

func getKrbConfig() (string) {
  return getEnvDefault(EnvKrbConfig, "/etc/krb5.conf")
}

func getOidcScope() (string) {
  return getEnvDefault(EnvOidcScope, "openid profile email")
}

func getOidcRedirectUri() (string) {
  return getEnvDefault(EnvOidcRedirectUri, "http://localhost/oidc")
}

func getOidcResponseType() (string) {
  return getEnvDefault(EnvOidcResponseType, "token id_token")
}

func getOidcAuthUrl() (string, error) {
  return getEnvRequired(EnvOidcAuthUrl)
}

func getOidcClientId() (string, error) {
  return getEnvRequired(EnvOidcClientId)
}

func getExecCredential(token string, err error, exp *time.Time) (string) {
  ec := ExecCredential{
    ApiVersion: "client.authentication.k8s.io/v1beta1",
    Kind: "ExecCredential",
    Status: ExecCredentialStatus{},
  }

  if err != nil {
    ec.Status.Error = err.Error()
  } else {
    ec.Status.Token = token
    if exp != nil {
      ec.Status.Expiration = exp.Format(time.RFC3339)
    }
  }

  if res, err := json.Marshal(&ec); err != nil {
    panic(err)
  } else {
    return string(res)
  }
}

func printError(err error) {
  logger.Printf("error: %s", err)
  fmt.Print(getExecCredential("", err, nil))
}

func printToken(token string, exp *time.Time) {
  fmt.Print(getExecCredential(token, nil, exp))
}

func getNonce() (string) {
  length := 10
  chars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
  rand.Seed(time.Now().UTC().UnixNano())

  b := make([]rune, length)
  for i := range b {
    b[i] = chars[rand.Intn(len(chars))]
  }

  logger.Printf("nonce (%d): %s", length, string(b))
  return string(b)
}

func findToken(loc string) (string, error) {
  key := "id_token"
  u, err := url.Parse(loc)
  if err != nil {
    return "", err
  }

  q := u.Query()
  token := q.Get(key)

  // Found it, return it
  if token != "" {
    return token, nil
  }

  // Try the query fragment
  q, err = url.ParseQuery(u.Fragment)
  if err != nil {
    return "", fmt.Errorf("unable to parse fragment: %s", err)
  }

  token = q.Get(key)
  if token != "" {
    return token, nil
  }

  return "", fmt.Errorf("unable to locate token")
}

func validateToken(token string) (string, error) {
  // TODO: do real validation here
  parts := strings.Split(token, ".")
  if len(parts) != 3 {
    return "", fmt.Errorf("malformed token, expected 3 parts, got %d", len(parts))
  }

  partOne, err := base64.RawStdEncoding.DecodeString(parts[0])
  if err != nil {
    return "", fmt.Errorf("unable to base64 decode headers: %s", err)
  }

  partTwo, err := base64.RawStdEncoding.DecodeString(parts[1])
  if err != nil {
    return "", fmt.Errorf("unable to base64 decode claims: %s", err)
  }

  var headerOut bytes.Buffer
  var claimsOut bytes.Buffer

  json.Indent(&headerOut, partOne, "", "  ")
  json.Indent(&claimsOut, partTwo, "", "  ")

  logger.Printf("header:\n%s", headerOut.Bytes())
  logger.Printf("claims:\n%s", claimsOut.Bytes())
  logger.Printf("signature:\n%s", parts[2])

  return token, nil
}

func main() {
  oidcAuthUrl, err := getOidcAuthUrl()
  if err != nil {
    printError(err)
    os.Exit(1)
  }

  oidcClientId, err := getOidcClientId()
  if err != nil {
    printError(err)
    os.Exit(1)
  }

  user, err := user.Current()
  if err != nil {
    printError(err)
    os.Exit(1)
  }

  oidcScope := getOidcScope()
  oidcRedirect := getOidcRedirectUri()
  oidcResponseType := getOidcResponseType()

  krbCache := getKrbCache(user.Uid)
  krbConfig := getKrbConfig()

  cfg, err := config.Load(krbConfig)
  if err != nil {
    printError(err)
    os.Exit(1)
  }

  cache, err := credentials.LoadCCache(krbCache)
  if err != nil {
    printError(err)
    os.Exit(1)
  }

  client, err := client.NewClientFromCCache(cache, cfg, client.Logger(logger))
  if err != nil {
    printError(err)
    os.Exit(1)
  }

  request, err := http.NewRequest("GET", oidcAuthUrl, nil)
  if err != nil {
    printError(err)
    os.Exit(1)
  }

  query := request.URL.Query()
  query.Add("client_id", oidcClientId)
  query.Add("response_type", oidcResponseType)
  query.Add("nonce", getNonce())
  query.Add("scope", oidcScope)
  query.Add("redirect_uri", oidcRedirect)
  requestUrl := query.Encode()

  request.URL.RawQuery = requestUrl
  logger.Printf("request %s", request.URL)

  httpClient := &http.Client{
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
      return http.ErrUseLastResponse
    },
  }

  spnegoClient := spnego.NewClient(client, httpClient, "")
  resp, err := spnegoClient.Do(request)
  if err != nil {
    printError(err)
    os.Exit(1)
  }

  resp.Body.Close()
  if resp.StatusCode != http.StatusFound {
    printError(fmt.Errorf("expected a 302, got %d", resp.StatusCode))
    os.Exit(1)
  } else {
    location := resp.Header.Get("Location")

    if location == "" {
      printError(fmt.Errorf("received 302, but no location found"))
      os.Exit(1)
    }

    if strings.HasPrefix(location, oidcRedirect) != true {
      printError(fmt.Errorf("expected prefix of %s, but received %s", oidcRedirect, location))
      os.Exit(1)
    }

    token, err := findToken(location)
    if err != nil {
      printError(fmt.Errorf("could not locate token: %s", err))
      os.Exit(1)
    }

    token, err = validateToken(token)
    if err != nil {
      printError(fmt.Errorf("error validating: %s", err))
      os.Exit(1)
    }

    // TODO: add expiration
    printToken(token, nil)
  }
}
