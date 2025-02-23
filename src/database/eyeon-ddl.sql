-- Had to load data on spc01 due to memory restrictions
--create table observations as select * from read_json('pf/*.json',union_by_name=true);

-- DDL generated by DBeaver: right click -> generate sql -> CREATE statement
CREATE TABLE observations (
    uuid UUID,
    bytecount UBIGINT,
    filename VARCHAR,
    compiler VARCHAR,
    hosts VARCHAR[],
    parent VARCHAR,
    signatures STRUCT(
        certs STRUCT(
			 "cert._version" VARCHAR, 
			 sha256 VARCHAR, 
			 serial_number VARCHAR, 
			 issuer_name VARCHAR, 
			 subject_name VARCHAR, 
			 issued_on TIMESTAMP, 
			 expires_on TIMESTAMP, 
			 signed_using VARCHAR, 
			 RSA_key_size VARCHAR, 
			 basic_constraints VARCHAR, 
			 key_usage VARCHAR, 
			 subject_alt_name VARCHAR, 
			 ext_key_usage VARCHAR, 
			 certificate_policies VARCHAR, 
			 issuer_sha256 VARCHAR,
			 "subject_alt_name_:" VARCHAR, -- weird formatting, but sometimes lief pulls a field out like this for some reason
			 "dNSName" VARCHAR,
			 "cert._type" VARCHAR,
			 "<unsupported>" VARCHAR -- dont know why lief pulls this out of certs sometimes, but schema will break without it
		)[],
		signers VARCHAR,
		digest_algorithm VARCHAR,
        sha1 VARCHAR,
		verification VARCHAR
	)[],
	imphash VARCHAR,
	telfhash VARCHAR,
	authentihash VARCHAR,
	authenticode_integrity VARCHAR,
	metadata JSON,
	magic VARCHAR,
	modtime TIMESTAMP,
	observation_ts TIMESTAMP,
	permissions VARCHAR,
	md5 UUID,
	sha1 VARCHAR,
	sha256 VARCHAR,
	target_os VARCHAR,
	ssdeep VARCHAR,
	detect_it_easy VARCHAR,
	defaults JSON,
);

-- Views from Grant J
-- Just the certs! With column names!		
create view raw_sigs
as
select uuid, unnest(signatures[1].certs,recursive:=true) from observations where
len(signatures)>0
;

create view raw_uniq_certs
as
SELECT * EXCLUDE (uuid), count(*) num_rows from raw_sigs group by all
;

create view raw_cert_issuer_fields
as
select 
  split(trim(unnest(split(issuer_name,','))),'=')[1] x509_field,
  split(trim(unnest(split(issuer_name,','))),'=')[2] x509_value
from main.raw_uniq_certs 
;

create view raw_cert_subject_fields
as
select 
  split(trim(unnest(split(subject_name,','))),'=')[1] x509_field,
  split(trim(unnest(split(subject_name,','))),'=')[2] x509_value
from main.raw_uniq_certs 
;
