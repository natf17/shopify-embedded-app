/*                         StoreAccessTokens
 * ---------------------------------------------------------------------------------------------------------------------------------------------|
 * |  id  |  		shop  		  |  		     access_token  			 	 |          salt 	           |		  scope                     | 
 * |--------------------------------------------------------------------------------------------------------------------------------------------|
 * | 4324 |  "lmdev.myshopify.com"  |   "tuyiujhvbgvhgvjyj7676tig76gi6gi7"   |    "sfjhrgmjshrgjhskjrh"    |  "read_inventory,write_inventory"  |
 * |____________________________________________________________________________________________________________________________________________|
 * 
 */




CREATE TABLE STOREACCESSTOKENS(
					id 		  			BIGINT 		  	NOT NULL		IDENTITY, 
					shop 			    VARCHAR(50)   	NOT NULL,
					access_token        VARCHAR(100)   	NOT NULL,
					salt                VARCHAR(100)    NOT NULL,
					scope 			    VARCHAR(200)    NOT NULL,					
					
					);