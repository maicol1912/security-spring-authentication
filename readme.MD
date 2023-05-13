## Entidad Usuarios
* en la entidad de usuarios debemos definir y extender de UserDetails que es una interfaz de la cual vamos a extender y utilizar sus metodos para la autenticacion y la autorizacion

### Dependencias necesarias para trabajar con JWT

            <dependency>
                <groupId>io.jsonwebtoken</groupId>
                <artifactId>jjwt-api</artifactId>
                <version>0.11.5</version>
            </dependency>

		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-impl</artifactId>
			<version>0.11.5</version>
		</dependency>

		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-jackson</artifactId>
			<version>0.11.5</version>
		</dependency>

