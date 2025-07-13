import { Controller, Get, Req, Res, HttpStatus } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { Request, Response } from 'express';

@Controller('auth')
export class AuthController {
  private readonly CLIENT_SECRET = process.env.CLIENT_SECRET;
  private readonly RESTAURATEUR_SECRET = process.env.RESTAURATEUR_SECRET;
  private readonly DELIVERY_SECRET = process.env.DELIVERY_SECRET;

  @Get()
  async authenticate(@Req() req: Request, @Res() res: Response) {
    console.log('Authentification inter-service');
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
      console.log('Token manquant');
      return res.status(HttpStatus.UNAUTHORIZED).send('Token manquant');
    }

    try {
      // Décoder le token sans vérification pour lire le claim 'service'
      const decoded = jwt.decode(token) as any;
      let secret: string;

      if (decoded.service === 'client') {
        if (!this.CLIENT_SECRET) {
          throw new Error('CLIENT_SECRET non défini');
        }
        secret = this.CLIENT_SECRET;
      } else if (decoded.service === 'restaurateur') {
        if (!this.RESTAURATEUR_SECRET) {
          throw new Error('RESTAURATEUR_SECRET non défini');
        }
        secret = this.RESTAURATEUR_SECRET;
      } else if (decoded.service === 'deliverer') {
        if (!this.DELIVERY_SECRET) {
          throw new Error('DELIVERY_SECRET non défini');
        }
        secret = this.DELIVERY_SECRET;
      } else {
        throw new Error('Service invalide dans le token');
      }

      // Vérifier le token avec le secret correspondant
      jwt.verify(token, secret);
      console.log('Token valide');
      return res.status(HttpStatus.OK).send('');
    } catch (err) {
      console.log('Token invalide:', err.message);
      return res.status(HttpStatus.UNAUTHORIZED).send('Token invalide');
    }
  }
}
