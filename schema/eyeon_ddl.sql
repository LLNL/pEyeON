CREATE TABLE observations (
  uuid VARCHAR PRIMARY KEY,
  bytecount INTEGER,
  compiler VARCHAR DEFAULT NULL,
  filename VARCHAR,
  filetype VARCHAR,
  imphash VARCHAR DEFAULT NULL,
  telfhash VARCHAR DEFAULT NULL,
  magic VARCHAR,
  md5 VARCHAR,
  modtime VARCHAR DEFAULT NULL,
  observation_ts VARCHAR,
  parent VARCHAR DEFAULT NULL,
  permissions VARCHAR DEFAULT NULL,
  sha1 VARCHAR,
  sha256 VARCHAR,
  ssdeep VARCHAR DEFAULT NULL,
  target_os VARCHAR DEFAULT NULL,
  authentihash VARCHAR DEFAULT NULL,
  authenticode_integrity VARCHAR DEFAULT NULL,
  default_filename VARCHAR DEFAULT NULL,
  manufacturer_org VARCHAR DEFAULT NULL,
  location VARCHAR DEFAULT NULL,
  filelocation VARCHAR DEFAULT NULL,
  machines VARCHAR DEFAULT NULL,
  os VARCHAR DEFAULT NULL,
  version VARCHAR DEFAULT NULL,
--  x-version VARCHAR DEFAULT NULL,
  detect_it_easy VARCHAR DEFAULT NULL
);

CREATE TABLE observations_metadata (
  observation_uuid VARCHAR PRIMARY KEY,
  filetype VARCHAR,
  OS VARCHAR DEFAULT NULL,
  peMachine VARCHAR DEFAULT NULL,
  peOperatingSystemVersion VARCHAR DEFAULT NULL,
  peSubsystemVersion VARCHAR DEFAULT NULL,
  peSubsystem VARCHAR DEFAULT NULL,
  peLinkerVersion VARCHAR DEFAULT NULL,
  peImport VARCHAR[] DEFAULT NULL,
  peIsExe BOOLEAN DEFAULT NULL,
  peIsDll BOOLEAN DEFAULT NULL,
  peIsClr BOOLEAN DEFAULT NULL,
  CompanyName VARCHAR DEFAULT NULL,
  FileDescription VARCHAR DEFAULT NULL,
  FileVersion VARCHAR DEFAULT NULL,
  LegalCopyright VARCHAR DEFAULT NULL,
  ProductName VARCHAR DEFAULT NULL,
  ProductVersion VARCHAR DEFAULT NULL,
  dllRedirectionLocal BOOLEAN DEFAULT NULL,
  EI_CLASS INTEGER DEFAULT NULL,
  EI_DATA INTEGER DEFAULT NULL,
  EI_VERSION INTEGER DEFAULT NULL,
  EI_OSABI INTEGER DEFAULT NULL,
  EI_ABIVERSION INTEGER DEFAULT NULL,
  E_MACHINE INTEGER DEFAULT NULL,
  elfDependencies VARCHAR[] DEFAULT NULL,
  elfRpath VARCHAR[] DEFAULT NULL,
  elfRunpath VARCHAR[] DEFAULT NULL,
  elfSoname VARCHAR[] DEFAULT NULL,
  elfInterpreter VARCHAR[] DEFAULT NULL,
  elfDynamicFlags VARCHAR[] DEFAULT NULL,
  elfDynamicFlags1 VARCHAR[] DEFAULT NULL,
  elfGnuRelro BOOLEAN DEFAULT NULL,
  elfComment VARCHAR[] DEFAULT NULL,
  elfNote VARCHAR[] DEFAULT NULL,
  elfOsAbi VARCHAR DEFAULT NULL,
  elfHumanArch VARCHAR DEFAULT NULL,
  elfArchNumber INTEGER DEFAULT NULL,
  elfArchitecture VARCHAR DEFAULT NULL,
  elfIsExe BOOLEAN DEFAULT NULL,
  elfIsLib BOOLEAN DEFAULT NULL,
  elfIsRel BOOLEAN DEFAULT NULL,
  elfIsCore BOOLEAN DEFAULT NULL,
  numBinaries INTEGER DEFAULT NULL,
  binaries JSON DEFAULT NULL,
  coffMachineType VARCHAR DEFAULT NULL,
  javaVersion VARCHAR DEFAULT NULL,
  aoutMagic VARCHAR DEFAULT NULL,
  blahField VARCHAR DEFAULT NULL,
  someField VARCHAR DEFAULT NULL,
  description VARCHAR DEFAULT NULL,
  FOREIGN KEY (observation_uuid) REFERENCES observations(uuid)
);

CREATE TABLE signatures (
  signature_id VARCHAR PRIMARY KEY,
  observation_uuid VARCHAR,
  signers VARCHAR,
  digest_algorithm VARCHAR,
  verification VARCHAR DEFAULT NULL,
  sha1 VARCHAR DEFAULT NULL,
  FOREIGN KEY (observation_uuid) REFERENCES observations(uuid)
);

CREATE TABLE certificates (
  sha256 VARCHAR PRIMARY KEY,
  signature_id VARCHAR,
  issuer_sha256 VARCHAR DEFAULT NULL,
  cert_version VARCHAR DEFAULT NULL,
  serial_number VARCHAR DEFAULT NULL,
  issuer_name VARCHAR DEFAULT NULL,
  subject_name VARCHAR DEFAULT NULL,
  issued_on VARCHAR DEFAULT NULL,
  expires_on VARCHAR DEFAULT NULL,
  signed_using VARCHAR DEFAULT NULL,
  RSA_key_size VARCHAR DEFAULT NULL,
  basic_constraints VARCHAR DEFAULT NULL,
  key_usage VARCHAR DEFAULT NULL,
  ext_key_usage VARCHAR DEFAULT NULL,
  certificate_policies VARCHAR DEFAULT NULL,
  FOREIGN KEY (signature_id) REFERENCES signatures(signature_id)
);

CREATE VIEW pe_metadata AS
SELECT observation_uuid, OS, peMachine, peOperatingSystemVersion, peSubsystemVersion, peSubsystem, peLinkerVersion, peImport, peIsExe, peIsDll, peIsClr, CompanyName, FileDescription, FileVersion, LegalCopyright, ProductName, ProductVersion, dllRedirectionLocal
FROM observations_metadata
WHERE filetype = 'PE' OR filetype = 'Malformed PE';

CREATE VIEW elf_metadata AS
SELECT observation_uuid, OS, EI_CLASS, EI_DATA, EI_VERSION, EI_OSABI, EI_ABIVERSION, E_MACHINE, elfDependencies, elfRpath, elfRunpath, elfSoname, elfInterpreter, elfDynamicFlags, elfDynamicFlags1, elfGnuRelro, elfComment, elfNote, elfOsAbi, elfHumanArch, elfArchNumber, elfArchitecture, elfIsExe, elfIsLib, elfIsRel, elfIsCore
FROM observations_metadata
WHERE filetype = 'ELF';

CREATE VIEW macho_metadata AS
SELECT observation_uuid, OS, numBinaries, binaries
FROM observations_metadata
WHERE filetype = 'MACHOFAT' OR filetype = 'MACHOFAT64' OR filetype = 'EFIFAT' OR filetype = 'MACHO32' OR filetype = 'MACHO64';

CREATE VIEW coff_metadata AS
SELECT observation_uuid, coffMachineType
FROM observations_metadata
WHERE filetype = 'COFF';

CREATE VIEW java_metadata AS
SELECT observation_uuid, javaVersion
FROM observations_metadata
WHERE filetype = 'JAVACLASS' OR filetype = 'JAR' OR filetype = 'WAR' OR filetype = 'EAR';

CREATE VIEW aout_metadata AS
SELECT observation_uuid, aoutMagic
FROM observations_metadata
WHERE filetype = 'A.OUT big' OR filetype = 'A.OUT little';

CREATE VIEW blah_metadata AS
SELECT observation_uuid, blahField
FROM observations_metadata
WHERE filetype = 'BLAH';

CREATE VIEW somethingelse_metadata AS
SELECT observation_uuid, someField
FROM observations_metadata
WHERE filetype = 'SOMETHINGELSE';

CREATE VIEW other_metadata AS
SELECT observation_uuid, description
FROM observations_metadata;
