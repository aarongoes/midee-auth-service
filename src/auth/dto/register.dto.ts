import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { Match } from '../../common/decorator/match.decorator';

export class RegisterDto {
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  @MaxLength(64)
  email: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  @MaxLength(32)
  password: string;

  @Match(RegisterDto, (o) => o.password)
  passwordConfirmation: string;
}
