# Data Clean Room Helper
This python script includes 3 functionalities (using `tpm2-tools`):
1. Create endorsement key (EK) and attestation key (AK/AIK)
2. Create a quote using TPM, hashes of several files, and a nonce
3. Verify a quote using TPM with a nonce, and check the hashes

## Notes
These commands may need `sudo` to run as some of the tools in `tpm2-tools` may require it to access the TPM.

## Usage
### Generate Keys
Generate EK and AK (for each machine that needs to be verified). On the host machine:
```sh
python main.py gen
```
This will put files in the `keys/` directory. The public AK `rsa_ak.pub` needs to be moved to the verifying machine.

### Generate reference quote
Create a quote from the EK and AK, hashing all necessary files. This will create the PCR that will be referenced against. Any changes to the hashed files require regenerating `pcr.bin`. On a machine known to be safe:
```sh
python main.py quote --output pcr.bin <FILES>
```
Hash all the files that need to be verified (in order). `pcr.bin` needs to be moved to the verifying machine.

### Generate quote
Create a quote from the EK and AK, hashing all necessary files. On the host machine:
```sh
python main.py quote --nonce <NONCE> --output pcr.bin <FILES>
```
Hash all the files that need to be verified (in order). The `quotes/pcr_quote.plain` and `quotes/pcr_quote.signature` need to be moved to the verifying machine for verification.

### Check quote
```sh
python main.py check_quote --nonce <NONCE> --pcr pcr.bin
```
This will require (from the previous steps, the paths can be passed in as command-line parameters):
- The public AK (expected at `keys/rsa_ak.pub`)
- `quotes/pcr_quote.plain`
- `quotes/pcr_quote.signature`
- `pcr.bin`

The program will return a non-zero exit code along with some log messages if the verification is not successful.
