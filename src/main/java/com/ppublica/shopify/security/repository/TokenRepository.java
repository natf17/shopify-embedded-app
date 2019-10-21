package com.ppublica.shopify.security.repository;

public interface TokenRepository {
	
	PersistedStoreAccessToken findTokenForStore(String store);
	void saveNewStore(PersistedStoreAccessToken accessToken);
	void updateStore(PersistedStoreAccessToken token);
	void uninstallStore(String storeName);
	
	
}
