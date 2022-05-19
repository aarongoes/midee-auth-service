import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { GetCurrentUserId } from 'src/common/decorator/get-current-user-id.decorator';
import { GetCurrentUser } from 'src/common/decorator/get-current-user.decorator';
import { Public } from 'src/common/decorator/public.decorator';
import { RtGuard } from 'src/common/guard/rt.guard';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { RegisterDto } from './dto/register.dto';
import { Tokens } from './type';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @Post('signup')
  @Public()
  @HttpCode(HttpStatus.CREATED)
  signUp(@Body() dto: RegisterDto): Promise<Tokens> {
    return this.authService.signUp(dto);
  }

  @Post('signin')
  @Public()
  @HttpCode(HttpStatus.OK)
  signIn(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signIn(dto);
  }

  @Post('signout')
  @HttpCode(HttpStatus.OK)
  signOut(@GetCurrentUserId() userId: number): Promise<boolean> {
    return this.authService.signOut(userId);
  }

  @Post('refresh')
  @Public()
  @UseGuards(RtGuard)
  @HttpCode(HttpStatus.OK)
  refreshToken(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser('refreshToken') refreshToken: string,
  ) {
    return this.authService.refreshToken(userId, refreshToken);
  }
}
