export interface Key {
    "jwk": {
        "e": string;
        "n": string;
        "kty": string;
        "kid": string;
        "use": string;
    }
    "created": number;
    "version": string;
    "key_type": string;
    "name": string;
    "protected_headers": {
        "kid": string;
        "enc": string
        [key: string]: any;
    }
}