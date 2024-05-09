All of the files in here are premade helm charts. I makes everything **MUCH** faster in terms of devops overhead


`helm upgrade --install postgres . -n ./postgres --values=./postgres/values.yaml --create-namespace`

`helm upgrade --install mariadb ./mariadb -n mariadb --values=values.yaml --create-namespace`

<!-- helm --install upgrade --create-namespace  -->