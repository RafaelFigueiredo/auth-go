# Como as senhas são guardadas nos sistemas de autenticação

O objetivo deste trabalho é apresentar um estudo sobre a evolução histórica dos sistemas de autenticação de usuários no que se refere a armazenamento de senhas e as boas práticas adotadas nesse processo. Alguns códigos foram inseridos apenas para exemplificar utilizando a linguagem Go.

## Conceitos Preliminares

### O que é autenticar?

Autenticar é verificar, testar, se uma determinada informação, que no caso é a autorização de acesso a um sistema é verdadeira ou não. O processo básico de autenticação é comparar um nome de usuário e senha fornecido com a informação registrada no sistema, se as informações coincidirem então é dado acesso ao sistema.

![Resultado de imagem para login form](C:\Users\Sec Acadêmica\Desktop\rafael\simple-login-form-with-blue-background.png)

```go
if username = "joe" && password == "senha"{
	fmt.Println("Bem vindo.")
}else{
	fmt.Println("Acesso negado!")
}
```

### O que é um Hash?

Um hash é uma string gerada através de um algoritmo de criptografia em uma unica direção, como por exemplo MD5 ou SHA1 e representa de forma única seu conteúdo original, por exemplo

```javascript
SHA1("Rafael") = 3e05c90f8530b1ba72519824415d05e08cf5718b
```

Sempre que eu codificar a palavra "Rafael" ela vai gerar "3e05c90f8530b1ba72519824415d05e08cf5718b", porém não é possível através do hash descobrir que a palavra original era "Rafael", por isso dizemos que essa é uma criptografia unidirecional. MD5 não é recomendado pois tem brechas de segurança que permitem que o conteúdos diferentes gerem o mesmo hash, o que seria extremamente preocupante caso a informação de uma transação como {To: 'Antonio da Feira', Amount: 3} pudesse ter o mesmo identificador que {To: 'Fundacao L...', Amount: 30000000}, não use MD5.

### O que é Cifra?

Por outro lado podemos estar interessados em recuperar a informação criptografada, existem algorimos que tanto encriptam, quanto desincriptam informação, desde que se saiba a **chave** utilizada. Esses algoritmos são chamados bidirecionais.

```go
//A variável senha vai armazenar a cifra gerada com o algoritmo DES da palavra "minhasenha", usando a chave "chavesecreta"
senha := DES.Encrypt("minhasenha", "chave secreta")

//Exemplificando a treta
fmt.Println( DES.Decrypt(senha,"chave secreta"))	// 'minha senha'
fmt.Println( DES.Decrypt(senha,"outra chave"))		// 'lkdsijoi987987kjh,mn' (gerou alguma coisa bizarra q não era nossa senha)
```



## Primeiros sistemas de autenticação

Nos primeiros sistemas multiusuários as informações de autenticação eram **gravadas de forma legível** em arquivos, que deviam ser protegidos pelo sistema operacional de acesso até mesmo de usuários com privilégios para isso, porém nada impedia que os dados fossem lidos diretamente nos discos de armazenamento ou mesmo o acesso a cópias do arquivo em fitas de backup guardadas em algum armário esquecido do prédio. 

| id   | user_name    | password |
| ---- | ------------ | -------- |
| 1    | Joe          | senha    |
| ...  |              |          |
| n    | Marie Currie | radio    |

Houve um caso emblematico quando um funcionário editava o arquivo de senhas, e um outro simultaneamente editava o arquivo com o boletim de notícias que era exibida aos usuários ao logarem, devido a arquitetura do sistema na época aconteceu que ao acessarem o sistema era exibido a lista das senhas de todos os usuários públicamente. Essa situação gerou apenas um grande desgaster administrativo de ter que alterar a senha de todos os usuários cadastrados, mas poderia ter sido bem pior.

## Surgimento dos algoritmos DES

Com o surgimento nos anos 70 do algoritmo de criptografia DES(Data Encryption Standart) que portava um algoritmo de cifragem de mensagens usada pelos americanos na segunda guerra para os computadores, foi possível começar a armazenar os dados de autenticação de forma cifrada, **não legível**.

| id   | user_name    | password                |
| ---- | ------------ | ----------------------- |
| 1    | Joe          | ea-a8-d5-e5-1d-a2-22    |
| ...  |              |                         |
| n    | Marie Currie | 31-d2-dc-63-7f-e4-e6-bd |

Mesmo que alguém tivesse acesso direto ao arquivo não seria possível descobrir qual a senha sem conhecer a chave usada para encripta-la.

Quando queriamos testar uma senha tinhamos que cifra-la, usando a mesma chave de encriptação, e comparar as duas cifras.

```go
//informação salva no sistema
joePassword = "ea	a8	d5	e5	1d	a2	22	e5"

//testando...
if DES("senha", "chave") == joePassword {
    log.Println("Bem vindo.")
}else{
    log.Println("Acesso negado!")
}
```

## O Bad Guy e Dicionários de senhas

Aqui apresentamos a figura do Bad Guy, que representa aquele ex-funcionário que tinha acesso livre ao sistema, um concorrente, alguma pessoa querendo tirar vantagem financeira ou que apenas se divirta com o caos. O Bad Guy de alguma forma teve acesso ao seu banco de dados, e nesse momento você pensa "sem problemas, ta tudo criptografado, ele não vai conseguir descobrir as senhas, segue o baile."

Então, nós humanos somos preguiçosos e temos uma memória limitada, a senha que cadastramos em sistemas por ai são palavras que precisamos decorar, pode ser o nome de um animal de estimação, telefone, data de nascimento dos filhos, etc. O Bad Guy vai se aproveitar disso, ele pode com base em um arquivo de palavras de um dicionário, fazer permutações dessas palavras e gerar uma grande lista de possíveis senhas. Nesse ponto entra a primeira vulnerabilidade do DES, ele é rápido, então não demoraria muito tempo para testar todas as possibilidades.

Nesse cenário, se o Bad Guy tiver acesso ao banco de dados com as senhas criptografadas, ele vai ter apenas o trabalho de comparar as cifras que aparecem no banco de dados com as cifras que ele trouxe de casa e vai ter uma lista de usuário que tem senhas idiotas.

```go 
//Define o Modelo
type User struct{
    ID int
    Username string
    Password string
}

type Pswd struct{
    HashPassword string
    PlainPassword string
}

//Entrada
var dbCracked []User
var passwordDictionary []Pswd

//Saída
var Bobos []Users

//Acha os bobos
passwordDictionary = LoadPasswordListFromFile("minha lista.csv")
for _, user := range(dbCracked){
    for _, password := range(passwordDictionary){
        if user.Password == password.HashPassword{
            Bobos = append(Bobos, User{Username: user.Username,
                                       Password:password.PlainPassword})
        }
    }
}

//E aqui temos a lista com usuário|senha legível de todos que usaram senhas fáceis.
return Bobos

```

### Em busca de outros algoritmos e AES

A "segurança" de um algoritmo de criptografia muitas vezes é determinado pelo simples fato dele nunca ter sido quebrado, por isso chamado de algoritmo heuristico. 

**DES** é considerado inseguro, devido ao tamanho curto da sua chave(56bits) e também a velocidade, é muito sussetivel a força bruta.

Geralmente utilizo o **Bcrypt** em meus projetos, ele foi um dos finalistas do concurso para se tornar AES(Advanced Encrypt Standart), pois ele é lento, o custo computacional para gerar e testar cada chave pode ser passado como parâmento. Dois segundos de espera para salvar a senha de um usuário se cadastrando podem significar meses para um hacker gerar uma lista com milhares de senhas possíveis.

O algoritmo escolhido para ser o **AES** foi o **Rijndael**, e é amplamente utilizado no mundo, desde instituições financeiras até orgãos de defesa. Tem chaves de 128,196 e 256 bits, e é considerado amplamente imune a ataques de força bruta.

> "An encryption standard
>
> The mid-1970s saw two major public (i.e., non-secret) advances. First was the publication of the draft Data Encryption Standard in the U.S. Federal Register on 17 March 1975. The proposed DES was submitted by IBM, at the invitation of the National Bureau of Standards (now NIST), in an effort to develop secure electronic communication facilities for businesses such as banks and other large financial organizations. After 'advice' and modification by the NSA, it was adopted and published as a Federal Information Processing Standard Publication in 1977 (currently at FIPS 46-3). DES was the first publicly accessible cipher to be 'blessed' by a national agency such as NSA. The release of its specification by NBS stimulated an explosion of public and academic interest in cryptography.
>
> DES was officially supplanted by the Advanced Encryption Standard (AES) in 2001 when NIST announced FIPS 197. After an open competition, NIST selected Rijndael, submitted by two Flemish cryptographers, to be the AES. DES, and more secure variants of it (such as 3DES or TDES; see FIPS 46-3), are still used today, having been incorporated into many national and organizational standards. However, its 56-bit key-size has been shown to be insufficient to guard against brute force attacks (one such attack, undertaken by the cyber civil-rights group Electronic Frontier Foundation, succeeded in 56 hours -- the story is in Cracking DES, published by O'Reilly and Associates). As a result, use of straight DES encryption is now without doubt insecure for use in new cryptosystem designs, and messages protected by older cryptosystems using DES, and indeed all messages sent since 1976 using DES, are also at risk. Regardless of its inherent quality, the DES key size (56-bits) was thought to be too small by some even in 1976, perhaps most publicly by Whitfield Diffie. There was suspicion that government organizations even then had sufficient computing power to break DES messages; clearly others have achieved this capability." (https://www.codesandciphers.org.uk/heritage/ModSec.htm)

### Uma pitada de sal (Salt)

Uma técnica para torna a vida do Bad Guy extremamente difícil é adicionar um salt, uma pequena porção de informação aleatória ao que queremos criptografar ou a chave.

```go
//Gera um numero aleatório baseado no tempo e num inteiro também aleatório, existem algoritmos específicos para gerar salts
salt := string(time.Now().Unix() * rand.Int(100000000))

password := salt + " : " + SHA1("senha"+ salt, "chave")
```

O salt deve ser armazenado junto com o hash gerado para podermos comparar a senha posteriormente, porém com essa simples técnica, o BadGuy vai ter que gerar e testar todo um dicionário por usuário cadastrado. Então mesmo no pior dos casos em que alguém mal intensiodado tiver acesso a base de dados, ele tera o trabalho de meses para identificar uma unica senha e não toda a base.

| id   | user_name    | password                                      |
| ---- | ------------ | --------------------------------------------- |
| 1    | Joe          | 17 : 6d607561ee5df3d97800eeac1544fdf1d60ad19c |
| ...  |              |                                               |
| n    | Marie Currie | 88 : d10992be649b5ab93057db92a7471107ee1e43b4 |

## A ameaça dos chips de criptográfia

Existem chips dedicados para criptografia e isso representa um problema, visto que o Bad Guy pode montar sistemas para testar senhas baseado em hardware 3 vezes mais rápido. Alguns algoritmos são controlados pela ITAR(International Traffic in Arms Regulations).

> #### NSA Product Types
>
> Depending on the required (and allowed) level of security, the NSA has defined various Types of encryption. The lower the number, the higher the security level. E.g. Type 1 products are for use by the US government for top secret material [3]. The following Product Types are known:
>
> 1. **Classified or sensitive US Government information - TOP SECRET**
>    This includes algorithms such as AES(256), BATON, FIREFLY, HAVEQUICK, and SAVILLE, that are used in products like the STU-III secure phone and many military communication products, like the KG-84, KIV-7, KY-57 and KY-99. Type 1 products are only used by the US Government, their contractors, and federally sponsored non-US Government activities, in accordance with the International Traffic in Arms Regulations (ITAR). Type 1 algorithms are also used by NATO and by the administrations of some NATO countries.
> 2. **National Security Information**
>    Includes products like CORDOBA, KEA and SKIPJACK used in equipment like the Cypris cypto chip and the Fortezza (Plus) crypto cards. It may be used for unclassified national security information. The equipment is unclassified, but the algorithms and keys are. Type 2 products are subject to International Traffic in Arms Regulations (ITAR).
> 3. **Unclassified sensitive US Government or commercial information**
>    Also known as Sensitive, But Unclassified (SBU); used on non-national security systems. Approved (unclassified) algorithms include DES, Tripple DES 1 , AES, DSA and SHA. 
>    A good example of a Type 3 product is the CVAS III secure phone.
> 4. **Unevaluated commercial cryptographic equipment; not for government usage**
>    The algorithms have been registered with NIST but are not Federal Information Processing Standard (FIPS). They may not be used for classified information.
>
> https://www.cryptomuseum.com/intel/nsa/index.htm



## Conclusão

O jeito mais adequado de armazenar as senhas nos servidores é de forma criptograda, com um algoritmo resistente a força bruta ou que envolva um alto custo computacional, AES ou BCrypt respectivamente, e utilizando um salt aleatório para impossibilitar a utilização de dicionários de senhas.