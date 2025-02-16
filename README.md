# Exporter Apex Central

## Description du projet

Ce projet est un **Exporter Apex Central** pour l'exportation de metrics dans **Prometheus**. Ces metrics correspondent aux logs les plus récents enregistrés dans la catégorie Virus/Malwares dans **Apex Central**.

## Contexte de base

Ce projet a été créé à la suite d'un besoin de centralisation des alertes de logs provenant de différents applications de sécurité, d'antivirus ou de firewalls pour les transférer sur une application de visualisation de données permettant la visualisation sous la forme de graphiques et de tableaux de bord, comme **Grafana** par exemple.

## Prérequis

Pour utiliser ce projet, il faut:
* Avoir [Docker](https://www.docker.com/get-started/) d'installé sur la machine.

## Installation de l'Exporter

Pour installer l'Exporter, il vous suffit de créer une image Docker du projet à l'aide du `Dockerfile` fournis. Pour ce faire, la commande est la suivante.

Dans le terminal, entrez la commande :

```bash
$ docker build . -t apex_exporter
```
> :memo: **Note:** Assurez-vous d'être dans le répertoire du projet `apex/` avant d'exécuter la commande ci-dessus.

L'image **apex_exporter** doit être créée : 

```bash
$ docker images
```

## Exécuter l'Exporter

Pour lancer l'Exporter, il suffit d'entrer la commande suivante dans le terminal :

```bash
$ docker run --rm -v </path/to/your/username>/apex/config.yml:/apex/config.yml -p 9400:9400 apex_exporter
```

## Structure du fichier de configuration

Voici la structure fichier de configuration ***config.yml*** qui stocke les paramètres de l'API Apex Central.

```yaml
api_apex:
  id: api_private_id
  key: XX-X-X-X-XXX
  url: https://api.url.com
```

> :bulb: **Tip:** Les valeurs indiquées ne sont que des exemples.

## Dashboard Grafana

Dans le fichier `Apex_Central-1685537311706.json` contient la configuration du dashboard au format *JSON* directement importable dans Grafana.

Voici à quoi ressemble le dashboard :

![ApexCentralDashboard](https://github.com/Dyl-LAN741/apex/blob/main/png/dashboard_apex_central.png)
