async function encryptData(data, key) {
    const encodedData = new TextEncoder().encode(data);
    return await crypto.subtle.encrypt({ name: "AES-GCM", iv: key.iv }, key.cryptoKey, encodedData);
  }
  
  async function decryptData(encryptedData, key) {
    return new TextDecoder().decode(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv: key.iv }, key.cryptoKey, encryptedData)
    );
  }