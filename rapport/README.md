# README - Rapport de Stage LaTeX

## Structure du Projet

Ce rapport de stage professionnel a été généré en analysant l'ensemble du projet SIEM/SOAR développé par Med10S dans le cadre de son PFA GTR S4. Le rapport est structuré de manière modulaire pour faciliter la maintenance et les modifications.

## Fichiers Principaux

### Document Principal
- `main.tex` : Document maître avec configuration complète
- `bibliography.bib` : Références bibliographiques académiques

### Sections du Rapport
- `sections/remerciements.tex` : Page de remerciements
- `sections/resume.tex` : Résumé exécutif en français
- `sections/abstract.tex` : Abstract en anglais
- `sections/abreviations.tex` : Liste des abréviations
- `sections/introduction.tex` : Introduction générale détaillée
- `sections/structure_projet.tex` : Structure et architecture du projet
- `sections/conclusion.tex` : Conclusion et analyse des résultats
- `sections/perspectives.tex` : Perspectives d'évolution
- `sections/annexes.tex` : Annexes techniques
- `sections/glossaire.tex` : Glossaire des termes techniques

## Compilation

### Prérequis
- Distribution LaTeX complète (TeX Live, MiKTeX)
- Packages requis : voir `main.tex` pour la liste complète

### Commandes de Compilation

```bash
# Compilation standard
pdflatex main.tex
biber main
pdflatex main.tex
pdflatex main.tex

# Ou avec latexmk (recommandé)
latexmk -pdf -interaction=nonstopmode main.tex
```

### Compilation Automatisée avec Makefile

Créer un fichier `Makefile` :

```makefile
.PHONY: all clean distclean

MAIN = main
PDF = $(MAIN).pdf
TEX = $(MAIN).tex

all: $(PDF)

$(PDF): $(TEX) sections/*.tex bibliography.bib
	latexmk -pdf -interaction=nonstopmode $(MAIN)

clean:
	latexmk -c $(MAIN)
	rm -f *.bbl *.run.xml

distclean: clean
	latexmk -C $(MAIN)
	rm -f $(PDF)

view: $(PDF)
	xdg-open $(PDF) 2>/dev/null || open $(PDF) 2>/dev/null || start $(PDF)

watch:
	latexmk -pdf -pvc -interaction=nonstopmode $(MAIN)
```

Utilisation :
```bash
make          # Compile le rapport
make clean    # Nettoie les fichiers temporaires
make view     # Ouvre le PDF
make watch    # Compilation automatique à chaque modification
```

## Fonctionnalités du Rapport

### Formatage Professionnel
- Mise en page académique avec marges optimisées
- Numérotation des pages et sections automatique
- Table des matières, liste des figures et tableaux
- Bibliographie avec style IEEE
- Index automatique des termes techniques

### Contenu Technique
- Analyse complète de l'architecture SIEM/SOAR
- Métriques de performance détaillées
- Configurations techniques en annexe
- Scripts d'automatisation documentés
- Résultats des tests de sécurité

### Structure Modulaire
- Chaque section dans un fichier séparé
- Facilite la maintenance et les modifications
- Permet le travail collaboratif
- Réutilisable pour d'autres projets

## Personnalisation

### Modification du Contenu
Pour modifier une section, éditer le fichier correspondant dans `sections/`

### Ajout de Nouvelles Sections
1. Créer un nouveau fichier `.tex` dans `sections/`
2. Ajouter `\input{sections/nouveau_fichier}` dans `main.tex`
3. Recompiler le document

### Modification du Style
Les paramètres de formatage sont dans `main.tex` :
- Police et taille
- Marges et espacement
- Couleurs des liens
- Style de la bibliographie

## Contenu du Projet Analysé

Le rapport couvre l'ensemble du projet cybersécurité hospitalier :

### Architecture Technique
- **Couche Détection** : Suricata IDS/IPS, ModSecurity WAF
- **Couche Analyse** : Wazuh SIEM avec rules personnalisées
- **Couche Orchestration** : TheHive, Cortex, MISP, n8n
- **Couche Présentation** : Dashboards et APIs

### Scénarios d'Attaque Testés
- EternalBlue (MS17-010)
- Attaques XSS sur applications web
- Sites web malveillants
- Brute force SSH
- Déni de service distribué

### Métriques de Performance
- Taux de détection : 89.5% moyen
- Temps de réponse : 1.2s moyen
- Couverture MITRE ATT&CK : 80%+
- Intégration API : 95% succès

## Support et Documentation

### Logs de Compilation
Les erreurs de compilation sont généralement dues à :
- Packages manquants
- Caractères spéciaux non échappés
- Références bibliographiques cassées

### Dépannage Courant
- Erreur biber : `biber --cache` puis recompiler
- Erreur hyperref : vérifier les labels dupliqués
- Erreur encoding : utiliser UTF-8

### Contact
Pour toute question sur le rapport ou le projet SOAR :
- Auteur : Mohammed sbihi (GTR S4)
- Encadrement : Équipe pédagogique GTR
- Institution : ENSAF

## Licence et Utilisation

Ce rapport est destiné à un usage académique dans le cadre du PFA GTR S4. 
La réutilisation du template LaTeX est encouragée pour d'autres projets étudiants.

---

*Généré automatiquement à partir de l'analyse du projet SIEM/SOAR hospitalier - 2025*
