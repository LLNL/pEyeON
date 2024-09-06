-- Some simple DQA on the observation data
-- Assumes eyeon-ddl.sql has been run to create the views

summarize observations;

select * from observations where len(signatures) > 0
;

-- Cluster observations by time. Were you expecting many small clusters or a few large or ???
select time_bucket(INTERVAL '15 minutes', observation_ts), count(*) from observations group by all order by all
;

summarize raw_sigs
;

--- Based on the raw_uniq_certs, how do prevalent are different features?  
select count(*) num_rows, * EXCLUDE (uuid) from raw_sigs group by all order by num_rows desc
;

select signed_using, rsa_key_size, count(*) from main.raw_uniq_certs group by all order by ALL 
;

select basic_constraints, count(*) from main.raw_uniq_certs group by all order by ALL
;

select ext_key_usage, count(*) from main.raw_uniq_certs group by all order by ALL 
;

select key_usage, count(*) from main.raw_uniq_certs group by all order by ALL 
;

select basic_constraints, ext_key_usage, key_usage, count(*) from main.raw_uniq_certs group by all order by ALL 
;


--- Let's dig into the issuer and subject fields a bit

select x509_field, x509_value, count(*) from main.raw_cert_issuer_fields group by all order by all

select x509_field, x509_value, count(*) from main.raw_cert_subject_fields group by all order by all
;

-- Flattens existing defaults. They're all the same value, so not too interesting yet.
select *, count(*) from (		
select unnest(defaults,recursive:=true) from observations) group by all


-- Experimental/Dev below for working with nested structures ----------------------------------------------------
-- TL;DR: See eyeon-ddl for use of UNNEST and split which work better and are more readable

-- Try supplying the structure:
create or replace view pf1 as select * from read_json_auto('/Users/johnson30/data/eyeon/pf/Aspose.Slides.dll.11bb22a9947c97b0026d79ec9c808e4c.json');

summarize pf1

select * from read_json('/Users/johnson30/data/eyeon/pf/Aspose.Slides.dll.11bb22a9947c97b0026d79ec9c808e4c.json',
columns = {signatures: ''


select json_structure(json('[{"certs": [{"cert._version": "3","sha256": "c977923c771e1a66c925a2b6f501732e678dc9887afe6bfaac039d1d9a71f0ec"}]}]'))


select unnest(signatures) from pf1

select unnest(json('[{"certs": [{"cert._version": "3","sha256": "c977923c771e1a66c925a2b6f501732e678dc9887afe6bfaac039d1d9a71f0ec"}]}]'))

,
                    "serial_number": "04:00:00:00:00:01:2F:4E:E1:52:D7",
                    "issuer_name": "C=BE, O=GlobalSign nv-sa, OU=Root CA, CN=GlobalSign Root CA",
                    "subject_name": "C=BE, O=GlobalSign nv-sa, CN=GlobalSign Timestamping CA - G2",
                    "issued_on": "2011-04-13 10:00:00",
                    "expires_on": "2028-01-28 12:00:00",
                    "signed_using": "RSA with SHA1",
                    "RSA_key_size": "2048 bits",
                    "basic_constraints": "CA=true, max_pathlen=0",
                    "key_usage": "Key Cert Sign, CRL Sign",
                    "certificate_policies": "Any Policy"
				}]
		}]'))


{userId: 'UBIGINT',
                          id: 'UBIGINT',
                          title: 'VARCHAR',
                          completed: 'BOOLEAN'});


summarize observations

-- Its an array, but they're all only len 1
select len(signatures) num_sigs, count(*) from observations group by all


-- extract from list, summarize
select signatures[1] from observations where len(signatures)>0

-- Are the structures all the same? Nope.
select json_structure(cast(signatures[1] as json)), count(*) from observations where len(signatures)>0 group by all

-- Extract a top-level field
select json_extract(cast(signatures[1] as json),'signers') signers, count(*) from observations where len(signatures)>0  and signers not ilike '%microsoft%' group by all order by count(*) desc

-- CERTs is a nested list, extract and count
select filename,json_extract(cast(signatures[1] as json),'certs') certs, count(*) from observations where len(signatures)>0  and certs not ilike '%microsoft%' group by all order by count(*) desc

-- CERTs is a nested list, extract and count
select filename, unnest(certs) cert from (
summarize
	select
		filename,
		json_extract(cast(signatures[1] as json),'certs') certs
	from
		observations
	where
		len(signatures)>0
		and certs not ilike '%microsoft%' 
)

-- Unpack CERTs
summarize select json_structure(json_extract(cast(signatures[1] as json),'certs')) certs from observations where len(signatures)>0


select len(json_extract(cast(signatures[1] as json),'certs')) num_certs, count(*) from observations where len(signatures)>0 group by all order by count(*) desc



select metadata, count(*) from observations group by all order by count(*) desc

select filename, count(distinct observation_ts), count(*) from observations group by all having count(*) > 1 order by count(*) desc

select filename, count(distinct observation_ts) num_ts, count(*) from observations group by all having num_ts > 1 order by count(*) desc

select *, count(*) num_dups from observations group by all having num_dups>1

select sha256, count(*) from observations group by all having count(*) > 1

-- Are signatures consistent?
select len(signatures) num_sigs, count(*) from observations group by all 

-- Fully unnests, but may be tricky separating top level sig from nested certs:
select unnest(signatures,recursive:=true) from observations where
		len(signatures)>0
