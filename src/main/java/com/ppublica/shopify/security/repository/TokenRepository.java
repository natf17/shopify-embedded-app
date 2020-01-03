package com.ppublica.shopify.security.repository;

/**
 * Provides methods for directly interacting with the repository that contains the OAuth tokens.
 * @author N F
 *
 */
public interface TokenRepository {
	
	/**
	 * Find the shop that matches the full shop name provided.
	 * 
	 * @param store The full shop name
	 * @return The PersistedStoreAccessToken that matches the shop name, or null if not found
	 */
	PersistedStoreAccessToken findTokenForStore(String store);
	
	/**
	 * Save a new store.
	 * 
	 * @param accessToken The PersistedStoreAccessToken to persist
	 */
	void saveNewStore(PersistedStoreAccessToken accessToken);
	
	/**
	 * Update the info for an existing store.
	 * 
	 * @param token The PersistedStoreAccessToken with the updated info
	 */
	void updateStore(PersistedStoreAccessToken token);
	
	/**
	 * Uninstall completely the store that matches the given full shop domain.
	 * 
	 * @param storeName The full store domain
	 */
	void uninstallStore(String storeName);
	
	
}
