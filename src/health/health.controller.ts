import { Controller, Get } from '@nestjs/common';
import { Public } from 'src/auth/decorators/public.decorator';
import { HealthService } from './health.service';
import {
  ApiOkResponse,
  ApiOperation,
  ApiServiceUnavailableResponse,
  ApiTags,
} from '@nestjs/swagger';
import { ErrorResponseDto } from 'src/common/dto/error-response.dto';
import {
  HealthResponseDto,
  ReadinessResponseDto,
} from './dto/health-response.dto';

@ApiTags('Health')
@Controller()
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Public()
  @Get('health')
  @ApiOperation({ summary: 'Liveness endpoint' })
  @ApiOkResponse({ type: HealthResponseDto })
  getHealth() {
    return this.healthService.getHealth();
  }

  @Public()
  @Get('ready')
  @ApiOperation({ summary: 'Readiness endpoint with dependency checks' })
  @ApiOkResponse({ type: ReadinessResponseDto })
  @ApiServiceUnavailableResponse({ type: ErrorResponseDto })
  getReadiness() {
    return this.healthService.getReadiness();
  }
}
