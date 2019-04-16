#function for checking the type of a hash (MD5, SHA1, SHA256, SHA384, SHA512) given in Binary or Hexadecimal

hashval <- function(hash){
        hashval_hash <- list(valid="",type="", format="",hash="")
        if (nchar(hash) == 128 && grepl("[01]{128}",hash)==TRUE){
                print("Valid MD5 in Binary")
                hashval_hash[1] <- "TRUE"
                hashval_hash[2] <- "md5"
                hashval_hash[3] <- "binary"
                hashval_hash[4] <- hash
                hashval_hash <<- hashval_hash
        }else if (nchar(hash) == 32 && grepl("[[:xdigit:]]{32}",hash)==TRUE){
                print("Valid MD5 in Hexadecimal")
                hashval_hash[1] <- "TRUE"
                hashval_hash[2] <- "md5"
                hashval_hash[3] <- "hexadecimal"
                hashval_hash[4] <- hash
                hashval_hash <<- hashval_hash
        }else if (nchar(hash) == 160 && grepl("[01]{160}",hash)==TRUE){
                print("Valid SHA1 in Binary")
                hashval_hash[1] <- "TRUE"
                hashval_hash[2] <- "sha1"
                hashval_hash[3] <- "binary"
                hashval_hash[4] <- hash
                hashval_hash <<- hashval_hash
        }else if (nchar(hash) == 40 && grepl("[[:xdigit:]]{40}",hash)==TRUE){
                print("Valid SHA1 in Hexadecimal")
                hashval_hash[1] <- "TRUE"
                hashval_hash[2] <- "sha1"
                hashval_hash[3] <- "hexadecimal"
                hashval_hash[4] <- hash
                hashval_hash <<- hashval_hash
        }else if (nchar(hash) == 256 && grepl("[01]{256,}",hash)==TRUE){
                print("Valid SHA256 in Binary")
                hashval_hash[1] <- "TRUE"
                hashval_hash[2] <- "sha256"
                hashval_hash[3] <- "binary"
                hashval_hash[4] <- hash
                hashval_hash <<- hashval_hash
        }else if (nchar(hash) == 64 && grepl("[[:xdigit:]]{64}",hash)==TRUE){
                print("Valid SHA256 in Hexadecimal")
                hashval_hash[1] <- "TRUE"
                hashval_hash[2] <- "sha256"
                hashval_hash[3] <- "hexadecimal"
                hashval_hash[4] <- hash
                hashval_hash <<- hashval_hash
        }else if (nchar(hash)==384 && grepl("[01]{384,}",hash)==TRUE){
                print("Valid SHA384 in Binary")
                hashval_hash[1] <- "TRUE"
                hashval_hash[2] <- "sha384"
                hashval_hash[3] <- "binary"
                hashval_hash[4] <- hash
                hashval_hash <<- hashval_hash
        }else if (nchar(hash)==96 && grepl("[[:xdigit:]]{96}",hash)==TRUE){
                print("Valid SHA384 in Hexadecimal")
                hashval_hash[1] <- "TRUE"
                hashval_hash[2] <- "sha384"
                hashval_hash[3] <- "hexadecimal"
                hashval_hash[4] <- hash
                hashval_hash <<- hashval_hash
        }else if (nchar(hash)==512 && grepl("[01]{512,}",hash)==TRUE){
                print("Valid SHA512 in Binary")
                hashval_hash[1] <- "TRUE"
                hashval_hash[2] <- "sha512"
                hashval_hash[3] <- "binary"
                hashval_hash[4] <- hash
                hashval_hash <<- hashval_hash
        }else if (nchar(hash)==128 && grepl("[[:xdigit:]]{128}",hash)==TRUE && grepl("^[01]{4}", hash)==FALSE){
                print("Valid SHA512 in Hexadecimal") #the grep logical (grepl) checks if the given hash has 0s and 1s as the first 6 characters. This is just a silly mechanism to mitigate conflicts with hashes that have 128 characters that are not fully 0s and 1s. In that case it means that it was not classified as MD5 and moved on to the next loops. In the loop that checks for SHA512 hashes, the aforementioned hashed would be classified as a valid Hexadecimal SHA512. 
                hashval_hash[1] <- "TRUE"
                hashval_hash[2] <- "sha512"
                hashval_hash[3] <- "hexadecimal"
                hashval_hash[4] <- hash
                hashval_hash <<- hashval_hash
        }else {
                print("Not Valid Hash")
                hashval_hash[1] <- "FALSE"
                hashval_hash[4] <- hash
                hashval_hash <<- hashval_hash
        }
}

