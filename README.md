

In this project, we have two dependencies `a` and `b`.

It appears that a can require('b') and b can require('a'), even though neither a nor b declare each other
as dependencies.

Does anyone know if this behavior has been the same since early versions of NPM?

This project is NOT about circular dependencies. It's about dependencies in node_modules being able to
resolve other dependencies in node_modules with explicitly declaring them. 