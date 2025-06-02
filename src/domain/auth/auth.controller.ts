import { Controller, Get, Req, Res, HttpStatus } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { Request, Response } from 'express';

// Contrôleur pour gérer l'authentification des requêtes inter-services
@Controller('auth')
export class AuthController {
  // Clés secrètes pour les rôles pertinents (client uniquement)
  private readonly JWT_SECRETS = {
    client: process.env.CLIENT_SECRET
  };

  // Endpoint appelé par le middleware ForwardAuth de Traefik
  @Get()
  async authenticate(@Req() req: Request, @Res() res: Response) {
    // Récupérer le token JWT depuis l'en-tête Authorization
    const token = req.headers['authorization']?.split(' ')[1];

    // Vérifier si le token est présent
    if (!token) {
      return res.status(HttpStatus.UNAUTHORIZED).send('Token manquant');
    }

    try {
      let decoded: any = null;
      let userRole: string | null = null;

      // Essayer de valider le token avec chaque clé secrète
      for (const [roleKey, secret] of Object.entries(this.JWT_SECRETS)) {
        try {
          decoded = jwt.verify(token, secret);
          userRole = roleKey;
          break;
        } catch (err) {
          continue;
        }
      }

      // Si le token est invalide ou aucun rôle n'est trouvé
      if (!decoded || !userRole) {
        return res.status(HttpStatus.UNAUTHORIZED).send('Token invalide');
      }

      // Retourner simplement un 200 OK, pas d'en-têtes nécessaires
      res.status(HttpStatus.OK).send('');
    } catch (err) {
      return res.status(HttpStatus.BAD_REQUEST).send('Erreur d\'authentification');
    }
  }
}