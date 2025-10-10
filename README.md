## @hoajs/jwt

JSON Web Token(JWT) middleware for Hoa.

## Installation

```bash
$ npm i @hoajs/jwt --save
```

## Quick Start

```js
import { Hoa } from 'hoa'
import { jwt } from '@hoajs/jwt'

const app = new Hoa()
app.use(jwt({ secret: 'shhhh' }))

app.use(async (ctx) => {
  ctx.res.body = `Hello, ${ctx.state.user.name}!`
})

export default app
```

## Documentation

The documentation is available on [hoa-js.com](https://hoa-js.com/middleware/jwt.html)

## Test (100% coverage)

```sh
$ npm test
```

## License

MIT
