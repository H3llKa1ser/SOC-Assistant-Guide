# Mozilla Firefox

Tools:

1) DB Browser for SQLite (places.sqlite)

Browsing data stored location:

    C:\Users\USER\AppData\Roaming\Mozilla\Firefox\Profiles

Followed by the Regex format:

    [a-z0-9]{8}\.default.*

## Firefox Artifacts

| File / Directory Name            | Artefact Contents                                                      | File Type           |
|----------------------------------|-------------------------------------------------------------------------|---------------------|
| `places.sqlite`                  | Contains the browsing history and bookmark metadata                    | SQLite              |
| `logins.json` / `key4.db`        | Contains credentials saved through the browser                         | JSON / SQLite       |
| `cookies.sqlite`                 | Contains cookies from sites accessed                                   | SQLite              |
| `extensions.json` / extensions directory | Contains artefacts related to Firefox extensions                  | JSON / Folder       |
| `favicons.sqlite`                | Favicon metadata indicating sites accessed                             | SQLite              |
| `sessionstore-backups`           | Handles sessions and tabs metadata                                     | Folder (jsonlz4)    |
| `formhistory.sqlite`             | Contains input data submitted by the user in web forms                 | SQLite              |

### 1) Enumerate Firefox artifacts in each user's directory

    ls C:\Users\ | foreach {ls "C:\Users\$_\AppData\Roaming\Mozilla\Firefox\Profiles" 2>$null}

### 2) Place.sqlite artifact analysis

Open the DB file with DB Browser for SQLite

Use table to analyze browsing history

    moz_places

Go to last_visit_date column and convert epoch to human readable to get the time visited

    https://www.epochconverter.com/

Use table to find the download metadata

    moz_annos

### 3) Cookies.sqlite artifact analysis

Open the DB file in DB Browser for SQLite

Use table to analyze cookie data

    moz_cookies

Filter based on use-case
