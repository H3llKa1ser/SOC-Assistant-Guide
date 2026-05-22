# Index and sourcetype extraction

### 1) Index extraction

    | eventcount summarize=false index=* | dedup index | fields index

OR

    | rest /services/data/indexes | table title, totalEventCount, currentDBSizeMB


### 2) Sourcetype extraction

    | metadata type=sourcetypes index=* | table sourcetype, recentTime, totalCount

