-- Had to load data on spc01 due to memory restrictions
--create table raw_pf as select * from read_json('pf/*.json',union_by_name=true);

-- Just the certs! With column names!		
create view raw_sigs
as
select uuid, unnest(signatures[1].certs,recursive:=true) from raw_pf where
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

