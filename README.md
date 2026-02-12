![Tests](https://github.com/raffiware-dev/npm-excollect-api-client/actions/workflows/tests.yaml/badge.svg?branch=main)


ExCollect Javascript API client


# Quick start

Enter the following in a terminal window:

```
git https://github.com/raffiware-dev/npm-excollect-api-client.git
cd  npm-excollect-api-client
npm install
npm run build
```

## Instantiating API in TypeScript


```typescript
import { ExCollectClient } from 'excollect-client';

const client = new ExCollectClient({
  apiUrl:        'https://devapi.raffiware.io',
  rootAuthority: authorityPubKey,
});

```

## 📄 License

The ExCollect JavaScript API Client is provided under the [MIT License](https://opensource.org/licenses/MIT).
