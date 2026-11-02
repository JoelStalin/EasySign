# EasySign — instrucciones para agentes

## Palabra clave: `RETOMAR EASYSIGN`
Cuando el usuario escriba **`RETOMAR EASYSIGN`** (en cualquier combinación de mayúsculas), retoma este proyecto así:
1. Lee `docs/HANDOFF_CLOUD.md` completo y `CHANGE_TIMELINE.md`.
2. Ejecuta `git status`, `git branch -a` y `git log --oneline -15`; confirma que estás en `feat/easysign-oidc-rbac` o en una rama nueva creada desde ella.
3. Resume el estado **en español, en 10 líneas o menos**: qué está hecho, qué rama, qué pruebas pasan, qué falta.
4. Continúa con el **"Siguiente paso"** del traspaso sin pedir permiso para lo que ya está aprobado (Fase 2: PostgreSQL con aislamiento por empresa). Pregunta solo por decisiones que dependen del dueño (RNC de la SRL, proveedores, fusiones a `main`).
5. Al terminar cada bloque: pruebas (`rm -rf dist && npm run build && npm test`), commit en rama propia, push, y actualiza `docs/HANDOFF_CLOUD.md`.

## Reglas inamovibles
- Responde siempre en **español**.
- Rama propia por cambio; **nunca** commits en `main`/`dev`; sube cada commit de inmediato. `main` solo por PR y **solo con autorización del dueño**.
- **FastAPI prohibido.** Sin secretos en Git. Despliegues de producción solo por GitHub Actions.
- **Nada se envía a la DGII ni al INDOTEL sin confirmación expresa del dueño.** No afirmar cumplimiento DGII ni valor de firma digital.
- Los textos legales los valida un abogado; no presentar el análisis como dictamen.
- Commits terminan con `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; PR con `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

## Comandos
`npm ci` · `rm -rf dist && npm run build` · `npm test` (≈1 min). Borra `dist/` al cambiar de rama.
