# Sistema de Ocorrências Acadêmicas — Versão com Melhorias de Segurança

**Disciplina:** Segurança da Informação  
**Professor:** Edson Vaz Lopes  
**Curso:** Engenharia de Software — Católica SC  
**Data:** 05 de maio de 2026

## Descrição

Este repositório contém a versão melhorada do protótipo web de registro de ocorrências acadêmicas, desenvolvido como parte da atividade prática da disciplina de Segurança da Informação.

O sistema original foi analisado sob a perspectiva de segurança da informação, e diversas melhorias foram implementadas no HTML, CSS e JavaScript para mitigar os riscos identificados.

## Integrantes do Grupo

- Henrique Cordeiro de Oliveira, Lucas Rogério Mendonça e Nicholas Scoz dos Santos

## Links

- **Sistema publicado:** https://nicholasscoz.github.io/seguranca-da-informacao-ap01/
- **Repositorio:** https://github.com/nicholasscoz/seguranca-da-informacao-ap01.git

## Principais Melhorias Implementadas

1. **Controle de acesso por perfil (RBAC):** Permissões diferenciadas para aluno, professor e administrador
2. **Remoção do seletor livre de perfil:** Perfil fixo conforme login
3. **Sanitização contra XSS:** Toda renderização dinâmica é sanitizada
4. **Validação de campos obrigatórios:** Campos com validação HTML e JavaScript
5. **Minimização de dados (LGPD):** Removidos CPF, e-mail pessoal e telefone
6. **Expiração automática de sessão:** Timeout de 15 minutos com timer visual
7. **Bloqueio por tentativas de login:** Lockout após 5 tentativas falhas
8. **Exportação segura:** Sem senhas, tokens ou localStorage completo
9. **Token de API removido:** Credencial falsa removida do código
10. **Logs protegidos:** Visíveis apenas para administrador
11. **Confirmação para ações destrutivas:** Exclusão e reset exigem confirmação
12. **Senhas mais fortes:** Senhas de demonstração com maior complexidade
13. **Banner de aviso:** Informa que o sistema é protótipo didático
14. **Metadados de segurança:** Headers de segurança via meta tags
15. **Observações internas restritas:** Visíveis apenas para administradores

## Credenciais de Demonstração

| Perfil        | E-mail                      | Senha       |
|---------------|------------------------------|-------------|
| Aluno         | aluno@faculdade.local        | Demo@2026   |
| Professor     | professor@faculdade.local    | Demo@2026   |
| Administrador | admin@faculdade.local        | Admin@2026  |

## Tecnologias

- HTML5
- CSS3
- JavaScript (vanilla)
- Sem back-end, API ou banco de dados

## Aviso

Este é um protótipo didático. **Não insira dados reais.** Todas as proteções implementadas são simulações no front-end e podem ser contornadas via DevTools.
