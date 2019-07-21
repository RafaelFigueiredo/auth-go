# Sistema de Autenticação



[TOC]

## Objetivo

Sistema de autenticação com geração de JWT(Java Web Token) para ser consumido em chamadas via api e/ou controle de sessões (Cookies). O sistema será constituído de 3 partes:

1. Servidor com API de autenticação
2. Biblioteca para validação de tokens e implementação de middlewares
3. Área administrativa para gerenciamento de usuário e monitoramento do log de acesso.

## Conceitos a priori

* JWT
* Hash
* Chaves públicas e privadas

## Requisitos

* Opção de encryptar os dados públicos armazenados (payload) no token;

* Opção entre Bcrypt (padrão) ou AES como algoritmo de criptografia da assinatura (signature);

* Cookies devem ser armazenados como HttpOnly para mitigar ataques XSS(Cross Site Script)¹;

* Ao criar token preencher todos os clains da payload, principalmente:

  *  `aud`- Especifica a audiência do JWT
  * `iss`- Especifica o criador do JWT
  * `exp`- Especifica o tempo para o JWT expirar
  * `iat`- Especifica o timestamp de criação do JWT
  
* Ao validar o token deve ser verificado os claims acima listados.

  [1]: https://www.owasp.org/index.php/HttpOnly	"OWASP HttpOnly"

  

## Tecnologia escolhida

* Linguagem de programação: Golang
* Ambiente de execução: Heroku;
* Bancos de dados: PostgreSQL;

* Bibliotecas: 
  * gorilla mux
  * ...

## Modelo do Banco de Dados

## API

* Caminhos
  * `/api/login`
  * `/api/logout`

## Biblioteca

* Métodos públicos
  * Server.Start()
  * LoginHandler
  * LogoutHandler
  * ValidateTokenAPIMiddleware(r,w, nextHandler)
  * ValidateTokenCookieMiddleware(r,w, nextHandler)
* Métodos privados
  * createToken
  * signToken
  * validateToken