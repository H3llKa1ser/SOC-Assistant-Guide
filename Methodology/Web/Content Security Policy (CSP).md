# Content Security Policy (CSP).md

### 1) Check CSP Header on a site

    for i in 1 2 3; do   curl -s -D - -o /dev/null https://domain.local/     | grep -i '^content-security-policy'; done
