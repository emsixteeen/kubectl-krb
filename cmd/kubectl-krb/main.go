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
  "hash/crc32"
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
  EnvUserAgent = "USER_AGENT"
  EnvDebugEnabled = "DEBUG"
  EnvMaxErrorLength = "MAX_ERROR_LENGTH"
)

var (
  logger *log.Logger
  maxErrorLength int
)

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
  if v, err := strconv.ParseBool(os.Getenv(EnvDebugEnabled)); err != nil || v == false {
    logger = log.New(ioutil.Discard, "debug: ", log.LstdFlags)
  } else {
    logger = log.New(os.Stderr, "debug: ", log.LstdFlags)
  }

  if v, err := strconv.Atoi(os.Getenv(EnvMaxErrorLength)); err != nil {
    maxErrorLength = 120
    logger.Printf("error parsing env %s: %s, using %d", EnvMaxErrorLength, err, maxErrorLength)
  } else {
    maxErrorLength = v
    logger.Printf("parsed %s as %d", EnvMaxErrorLength, maxErrorLength)
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

func getUserAgent() (string) {
  return getEnvDefault(EnvUserAgent, "")
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
  msg := err.Error()

  if len(msg) > maxErrorLength {
    msg = msg[:maxErrorLength] + "..."
    err = fmt.Errorf(msg)
  }

  logger.Printf("error: %s", err)
  fmt.Print(getExecCredential("", err, nil))
  fmt.Fprintf(os.Stderr, "error: %s\n", err)
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

func validateToken(token string) (string, *time.Time, error) {
  // TODO: do real validation here
  parts := strings.Split(token, ".")
  if len(parts) != 3 {
    return "", nil, fmt.Errorf("malformed token, expected 3 parts, got %d", len(parts))
  }

  partOne, err := base64.RawURLEncoding.DecodeString(parts[0])
  if err != nil {
    return "", nil, fmt.Errorf("unable to base64 decode headers: %s", err)
  }

  partTwo, err := base64.RawURLEncoding.DecodeString(parts[1])
  if err != nil {
    return "", nil, fmt.Errorf("unable to base64 decode claims: %s", err)
  }

  var headerOut bytes.Buffer
  var claimsOut bytes.Buffer

  json.Indent(&headerOut, partOne, "", "  ")
  json.Indent(&claimsOut, partTwo, "", "  ")

  logger.Printf("header:\n%s", headerOut.Bytes())
  logger.Printf("claims:\n%s", claimsOut.Bytes())
  logger.Printf("signature:\n%s", parts[2])

  expiration := getTokenExpiration(partTwo)
  return token, expiration, nil
}

func getTokenExpiration(b []byte) (*time.Time) {
  var claims struct {
    Expiration int64 `json:"exp"`
  }

  if err := json.Unmarshal(b, &claims); err != nil {
    return nil
  }

  t := time.Unix(claims.Expiration, 0)
  return &t
}

func buildKrb5Config(in string) (cfg *config.Config, err error) {
  if strings.HasPrefix(in, "/") {
    cfg, err = config.Load(in)
    if err == nil {
      return
    }
  }

  cfg, err = config.NewConfigFromString(in)
  if err == nil {
    return
  }

  return nil, err
}

func cachedTokenPath(uid string) (string) {
  hash := crc32.NewIEEE()
  for _, e := range os.Environ() {
    hash.Write([]byte(e))
  }

  sum := hash.Sum([]byte{})
  return fmt.Sprintf("%s/oidc_ct_%s_%08x", os.TempDir(), uid, sum)
}

func getCachedToken(uid string) (string, *time.Time, error) {
  path := cachedTokenPath(uid)
  b, err := ioutil.ReadFile(path)
  if err != nil {
    return "", nil, fmt.Errorf("unable to load cached token: %s", path)
  }

  token, expiry, err := validateToken(string(b))
  if err != nil {
    return "", nil, fmt.Errorf("unable to validate cached token: %s", err)
  }

  if expiry.Before(time.Now()) {
    return "", nil, fmt.Errorf("cached token expired at %s", expiry)
  }

  return token, expiry, nil
}


func writeCachedToken(t, uid string) (error) {
  path := cachedTokenPath(uid)
  return ioutil.WriteFile(path, []byte(t), 0600)
}

func main() {
  user, err := user.Current()
  if err != nil {
    printError(err)
    os.Exit(1)
  }

  // Try and get a cached token first
  if token, expiration, err := getCachedToken(user.Uid); token != "" {
    logger.Printf("loaded cached token")
    printToken(token, expiration)
    return
  } else if err != nil {
    logger.Printf("error getting cached token: %s", err)
  }

  // Otherwise we're here
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

  oidcScope := getOidcScope()
  oidcRedirect := getOidcRedirectUri()
  oidcResponseType := getOidcResponseType()

  krbCache := getKrbCache(user.Uid)
  krbConfig := getKrbConfig()

  userAgent := getUserAgent()

  cfg, err := buildKrb5Config(krbConfig)
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

  if userAgent != "" {
    request.Header.Set("User-Agent", userAgent)
  }

  httpClient := &http.Client{
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
      if strings.HasPrefix(req.URL.String(), oidcRedirect) {
        return http.ErrUseLastResponse
      }

      return nil
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
    printError(fmt.Errorf("expected a 302, got %s", resp.Status))
    os.Exit(1)
  }

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

  token, expiration, err := validateToken(token)
  if err != nil {
    printError(fmt.Errorf("error validating: %s", err))
    os.Exit(1)
  }

  if err := writeCachedToken(token, user.Uid); err != nil {
    logger.Printf("error saving token: %s", err)
  }

  printToken(token, expiration)
}
