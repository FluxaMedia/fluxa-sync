update refresh_tokens set token = encode(digest(token, 'sha256'), 'hex') where length(token) <> 64;

create index if not exists refresh_tokens_token_idx on refresh_tokens(token);
