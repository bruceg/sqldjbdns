CREATE TABLE domain (
  id INT NOT NULL PRIMARY KEY,
  name TEXT NOT NULL
);
CREATE UNIQUE INDEX domain_skey ON domain(lower(name));

CREATE TABLE entry (
  domain INT NOT NULL REFERENCES domain(id),
  prefix TEXT NOT NULL,
  ttl INT NOT NULL,
  ip INET,
  master_ip BOOL,
  mx_name1 TEXT,
  mx_name2 TEXT,
  PRIMARY KEY(domain,prefix)
);
